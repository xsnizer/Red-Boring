# Define Subnets from Network Interfaces
$networkInterfaces = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -eq "Dhcp"}
$subnets = @()

foreach ($iface in $networkInterfaces) {
    $ip = $iface.IPAddress
    $subnet = ($ip -replace "\d+$", "")  # Extract base subnet
    $subnets += $subnet
}

Write-Host "Detected Subnets: $($subnets -join ', ')" -ForegroundColor Green

# Recommended Ports for Both Windows & Linux
$portsToScan = @(22, 80, 443, 53, 3389, 445, 135, 139, 5985, 389, 636, 1433, 25, 110, 143, 3306, 5432, 21, 23, 8080, 8081, 8443, 5900, 9200)

# Function: Scan for Active Hosts
function Scan-ActiveHosts {
    param ([string]$subnet)
    $liveHosts = @()

    Write-Host "Scanning active hosts in $subnet.0/24..." -ForegroundColor Cyan
    1..254 | ForEach-Object {
        $ip = "$subnet$_"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
            Write-Host "[+] Host is alive: $ip" -ForegroundColor Green
            $liveHosts += $ip
        }
    }
    return $liveHosts
}

# Function: Port Scan for Each Live Host
function Scan-OpenPorts {
    param ([array]$hosts, [array]$ports)
    $openPorts = @{}

    foreach ($host in $hosts) {
        foreach ($port in $ports) {
            if (Test-NetConnection -ComputerName $host -Port $port -InformationLevel Quiet) {
                Write-Host "[+] $host has port $port open" -ForegroundColor Yellow
                if (-not $openPorts[$host]) { $openPorts[$host] = @() }
                $openPorts[$host] += $port
            }
        }
    }
    return $openPorts
}

# Function: Get SMB Shares (if SMB is open)
function Get-SMB-Shares {
    param ([string]$host)
    try {
        $shares = Get-SmbShare -CimSession $host -ErrorAction SilentlyContinue
        if ($shares) {
            Write-Host "[+] SMB Shares on $host:" -ForegroundColor Magenta
            $shares | ForEach-Object { Write-Host "    - $_.Name" }
        }
    } catch {
        Write-Host "[-] Could not retrieve SMB shares for $host" -ForegroundColor Red
    }
}

# Function: Get NetBIOS Name
function Get-NetBIOS {
    param ([string]$host)
    $nbtOutput = nbtstat -A $host
    if ($nbtOutput) {
        Write-Host "[+] NetBIOS Name for $host: " -ForegroundColor Cyan
        Write-Host $nbtOutput
    }
}

# Function: Get Active Directory Computers (if domain joined)
function Get-ADComputers {
    try {
        $computers = Get-ADComputer -Filter * | Select-Object Name, DNSHostName
        Write-Host "[+] Active Directory Computers:" -ForegroundColor Blue
        $computers | ForEach-Object { Write-Host "    - $($_.DNSHostName)" }
    } catch {
        Write-Host "[-] Unable to query Active Directory." -ForegroundColor Red
    }
}

# Get network routes
Write-Host "`n[+] Retrieving network routes..." -ForegroundColor Cyan
Get-NetRoute | Format-Table -AutoSize

# Get ARP Cache
Write-Host "`n[+] Retrieving ARP Cache..." -ForegroundColor Cyan
Get-NetNeighbor -AddressFamily IPv4 | Format-Table -AutoSize

# Discover Active Hosts on all detected subnets
$allLiveHosts = @()
foreach ($subnet in $subnets) {
    $allLiveHosts += Scan-ActiveHosts -subnet $subnet
}

# Scan for open ports
Write-Host "`n[+] Scanning for open ports on discovered hosts..." -ForegroundColor Cyan
$portResults = Scan-OpenPorts -hosts $allLiveHosts -ports $portsToScan

# Retrieve SMB Shares and NetBIOS Name for Hosts with SMB (445) Open
foreach ($host in $portResults.Keys) {
    if ($portResults[$host] -contains 445) {
        Get-SMB-Shares -host $host
    }
    Get-NetBIOS -host $host
}

# Active Directory Query (if domain joined)
Write-Host "`n[+] Checking for Active Directory computers..." -ForegroundColor Cyan
Get-ADComputers

Write-Host "`n[✔] Scan Complete!" -ForegroundColor Green
