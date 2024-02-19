Get-Service

Get-Verb

Get-service
Get-Date


Get-Service 
Get-Process


Get-Service -Name RpcSs
Get-Service -Name "ALG","BITS"

Get-Process 

Get-Process -Id 6696,0
Set-Service -Name "ALG" -StartupType Automatic

Get-Service -Name ALG 
Get-Service -DisplayName 'ActiveX Installer (AxInstSV)' 


Set-Service -StartupType Automatic
Set-Service 
Get-ChildItem -Path "C:\Program Files" -Recurse
Get-Service 
New-TimeSpan 

#Bana BITS servisini durduran komutu yazın.
#Sonrada başlatan komutu yazın.
Start-Service -Name BITS
Stop-Service -Name "ALG","BITS"

Set-Service -Name BITS -Status Stopped
#Windows altındaki sadece fileları listeleyen komutu yazalım ve Recursive olsun.
Get-ChildItem -Path "C:\Windows" -Recurse -File


Get-Help -Name Set-Service

Set-Service -Name LanmanWorkstation -DisplayName "LanMan Workstation"
Set-Service -Name "ALG" -DisplayName "ALG Service Custom"

Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation"

get-help -Name new-smbshare -Full

New-SmbShare -Name Demo -Path C:\Selenium -FullAccess "Everyone"
Get-Help -Name Remove-SmbShare -ShowWindow
Remove-SmbShare -Name tmp,Demo
Remove-SmbShare -Name demo -Confirm:$false
Remove-SmbShare -Name demo -Force

Get-SmbShare

Get-WindowsUpdateLog
Get-Module

$env:PSModulePath.Split(';')

Get-Module -ListAvailable -name *SQL*

#Bana a ile başlayan servisleri ekranda gösterin.
Get-Service -Name a*

Install-Module -Name SqlServer
Get-Module -ListAvailable -Name *SQL*

Get-Command -Module SqlServer

Invoke-Sqlcmd -ServerInstance 172.16.20.21 -Database CM_TNT -Query "
    select * from Update_ComplianceStatus
" -Username sa -Password Deneme123456! -TrustServerCertificate

Get-Command -Verb Get -Noun *Firewall*
Get-Command -Verb * -Noun *service*
Get-Command -Verb * -Noun Service

#iki nokta arasındaki connection test eden cmdleti komutu bulun ve google.com a doğru 80 portunu test edin.
Get-Command -Verb test -Noun *connection* 
get-help -name test-connection -full
get-help -name test-netconnection -Full
Test-NetConnection -ComputerName google.com -Port 80

#Makine üzerindeki NetworkAdapter bilgisini getiren komutu bulalım ve çalıştıralım.
Get-Command -Verb Get -Noun "*Adapter*"
get-help -name get-netadapter -Full
Get-NetAdapter

#Makine üzerindeki IpAddress lerini getiren komutu bulun ve çalıştırın.
Get-Command -Verb get -Noun "*IpAddress*"
get-help -name get-netipaddress -full
Get-NetIPAddress
#Makine üzerinde dnsclientcache leri getiren komutu bulun ve çalıştırın.
Get-Command -verb get -noun "*Cache*"
get-help -name Get-DnsClientCache -full
Get-DnsClientCache
#notepad processi açın ve process durduran komutu bularak açtığınız notepad processini kapatın.

Get-Command -Verb * -Noun process
get-help -name Stop-Process  -full
Get-Process -Name mspaint
Stop-Process -Name mspaint

<cmdlet> | <cmdlet>

Get-Process -name mspaint 
Stop-Process -Name mspaint

Get-Process -Name mspaint | Stop-Process 
Get-Service -Name ALG | Set-Service -DisplayName "ALG Service"

get-service | Get-Member
Get-Process | Get-Member
Get-NetIPAddress | Get-Member

Get-Service -name ALG | Get-Member
Get-Service | Select-Object -Property Name,Status,StartType
Get-Process | get-member
Get-Process | Select-Object -Property Name,StartTime,Path

#Servisleri ekranda sadece isim ve starttype görecek şekilde getirelim
#ChildItem kullanarak ekranda name ve en son yazılma tarihini görecek şekilde bir komut yazalım.
#Processlri ekranda isim ve komut satırı bilgisi görecek şekilde gösterin.
#Makine üzerinde lokal firewall kurallarını getiren komutu bulun
#ve bu komuttan gelen değerleri ekranda Action,Direction ve displayname bilgilerini gösterin.
#Makine üzerinde ip adreslerini ekranda sadece IpAddress ve AddressFamily bilgisi olacak şekilde görelim
#