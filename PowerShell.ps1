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
Get-Service | Get-Member -Name "*name*","*start*"
Get-Service | Select-Object -Property Name,StartupType
#ChildItem kullanarak ekranda name ve en son yazılma tarihini görecek şekilde bir komut yazalım.
Get-ChildItem -Path C:\ | Get-Member
Get-ChildItem -Path C:\ | Select-Object -Property Name,FullName,LastWriteTime
#Processlri ekranda isim ve FileVersion --komut satırı bilgisi görecek şekilde gösterin.
Get-Process
Get-Process | Get-Member -Name "*command*"

Get-Process | Select-Object -Property Name,FileVersion,CommandLine
#Makine üzerinde lokal firewall kurallarını getiren komutu bulun
#ve bu komuttan gelen değerleri ekranda Action,Direction ve displayname bilgilerini gösterin.
Get-Command -verb get -Noun *firewall*
Get-NetFirewallRule | Get-Member -Name "*acti*"
Get-NetFirewallRule | 
    Select-Object -Property Action,Direction,Enabled,DisplayName 

#Makine üzerinde ip adreslerini ekranda sadece IpAddress ve AddressFamily bilgisi olacak şekilde görelim
Get-NetIPAddress | Select-Object -Property IPAddress,AddressFamily
Get-Process | Select-Object -First -Last -Skip -Unique
Get-Process | Select-Object -First 10
Get-Process | Select-Object -Skip 10 -First 10
Get-Process | Select-Object -Last 10

Get-Service | Select-Object -Property Status -Unique

Get-Process | Select-Object -First 1

Get-Process | Sort-Object -Property CPU
Get-Process | Sort-Object -Property CPU -Descending

1..100 | Sort-Object -Descending

Get-Process | Measure-Object

Get-Command | Measure-Object

Get-Process | Measure-Object -Property cpu -Sum -Average -Maximum -Minimum 

Get-Service | 
    Group-Object -Property Status

Measure-Command {

    Get-NetIPAddress | Select-Object -Property IPAddress,AddressFamily
    Get-Process | Select-Object -First 10
    Get-Process | Select-Object -Skip 10 -First 10


}

#Bana en çok cpu tüketen ilk 10 processi ekranda gösterin.
Get-Process | Sort-Object -Property CPU | Select-Object -Last 10
Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10
#C:\ dizini altındaki klasörlerin yazılma tarihlerine göre sıralama yapalım ve ekranda
#lastwritetime ve fullname değerlerini görelim.
Get-ChildItem -Path C:\ | 
    Sort-Object -Property LastWriteTime |
        Select-Object -Property FullName,LastWriteTime

#processlerin isimlerini unique olarak ekranda görelim.
Get-Process | Select-Object -Property name -Unique

@{
    n='eHostname';
    e={}
}

get-service | Select-Object -Property Name,MachineName
get-service | Get-Member

Measure-Command {
    get-service | Select-Object -Property Name,@{
        n='ercanHostName';
        e={hostname}
    }

}

Measure-Command {
    get-service | Select-Object -Property Name,@{
        n='ercanHostName';
        e={$env:COMPUTERNAME}
    }

}


get-service | Select-Object -Property Name,@{
    n='ercanHostName';
    e={$env:COMPUTERNAME}
}


Get-Process | Sort-Object -Property cpu -Descending |
Select-Object  -First 10 -Property Name,CPU,@{
n='2dvdCPU';
e={$PSItem.cpu/2}
}

#Processleri ekranda id ye göreli sıralı şekilde sadece id ve name olacak şekilde getirin.
#Sonrasında bir custom kolon ekleyin bu kolonun ismini siz verin
#fakat değeri id değerinin 2 katı olacak.
Get-Process | Sort-Object -Property id -Descending |
Select-Object -Property Name, id, @{
    n='2rpt2';
    e= {$PSItem.id * 2}
}

Get-Service | Select-Object -Property Name,@{
n='Ln';
e={$PSItem.name.ToUpper()}
}


Get-Disk | Get-Member
Get-Disk | Select-Object -Property *



Get-Disk | Select-Object -Property number,Size,AllocatedSize,@{
n='Size4GB';
e={$PSItem.size / 1GB}
},
@{
n='AllocatedSize4GB';
e={$PSItem.AllocatedSize / 1GB}
}

Get-HotFix


Get-Command -Verb * -Noun *time*

New-TimeSpan -Start 02/10/2024 -End (Get-Date) | Select-Object -ExpandProperty DAys
(New-TimeSpan -Start 02/10/2024 -End (Get-Date)).Days

(Get-Service -Name aLG).Status

"Ercan".Length
"Mustafa bayir".ToUpper()

Get-Date -Format "dd.MM.yyyy" 
(get-date).ToString("ddMMyyyy")

