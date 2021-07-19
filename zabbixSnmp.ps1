# Script para instalacao e configuracao do ZABBIX / Instalacao e configuracao do SNMP 
# Autor: Mauricio Menon (SMIN.DT - IEE3)   2021-07-15 
# Revisado em: 2021-07-17
# 
# powershell.exe -executionpolicy unrestricted
#
#Comunidade do SNMP definida em $communityName eve ser modificado para o projeto em questao
#
#TO DO - gravar log em um arquivo
#TO DO - verificar se o arquivo esta sendo rodado do C:\zabbix_agentd, se sim, apagar

$ErrorActionPreference = "SilentlyContinue"                             #no caso de erro, continue silenciosamente - "Continue" exibe e continua o script
$Null | Out-File log.txt
$Error.Clear()

#vars SNMP
$communityName = "CGMRS_SOPHO_RO"                                                       #comunidade SNMP                                                                           #1o valor da chave

#ZABBIX     %arrumar copia dos arquivos, apagar chave do registro em hklm SYSTEM\CurrentControlSet\Software servico do zabbix
    $dirAtual = Get-Location
    #$dirDestino = "c:\zabbix_agentd\"
    if((Test-Path -Path "c:\zabbix_agentd\" )){                                    #copia somente se diretório destino não existir
        New-Item -ItemType directory -Path "c:\zabbix_agentd\"
        Copy-Item -Path "$dirAtual\b*" -Destination "c:\zabbix_agentd\bin" -Recurse   #tambem cria o diretorio caso necessario, mas por clareza do codigo aparece separado
        Copy-Item -Path "$dirAtual\c*" -Destination "c:\zabbix_agentd\conf" -Recurse
    }
    Try {   
            # Ajuste ACL zabbix_agentd
            get-acl "c:\zabbix_agentd\bin\zabbix_agentd.exe" | Format-List | Out-File log.txt -Append
            $acl = get-acl "c:\zabbix_agentd\bin\zabbix_agentd.exe" 
            $identity = "BUILTIN\Administrators"
            $fileSystemRights = "FullControl"
            $type = "Allow"
            $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
            $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
            $Acl.SetAccessRule($fileSystemAccessRule)
            Set-Acl -Path "c:\zabbix_agentd\bin\zabbix_agentd.exe" -AclObject $acl
            # Fim Ajuste ACL zabbix_agentd

            # run as admin
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\" -PropertyType String -Name "c:\zabbix_agentd\bin\zabbix_agentd.exe" -Value "RUNASADMIN" -Force
            c:\zabbix_agentd\bin\zabbix_agentd.exe --config C:\zabbix_agentd\conf\zabbix_agentd_amd64.conf --install
            #c:\zabbix_agentd\bin\zabbix_agentd.exe --config C:\zabbix_agentd\conf\zabbix_agentd_amd64.conf --install
            Start-Process "c:\zabbix_agentd\bin\zabbix_agentd.exe" -ArgumentList @( "-i", "silent") -Wait
            Set-Service -Name "Zabbix Agent" -StartupType Automatic     ##c:\zabbix_agentd\bin\zabbix_agentd.exe  --start            
    } Catch {
            write-host "Erro na configuracao do agente ZABBIX - verifique o arquivo de log criado" 
    }


#SNMP 
$path="HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"       #security snmp
$key = Get-Item -LiteralPath $path
$name = '1'  
try {
    # comando de verificacao WS "Get-WindowsFeature SNMP-Service"  e w10 "windows server para w10: Get-Service -Name snmp-service"
    Get-WindowsFeature SNMP-Service | Out-File log.txt -Append
    Install-WindowsFeature SNMP-Service -IncludeManagementTools   -IncludeAllSubFeature          #se ja esta instalado simplesmente prossegue

    #Configuracao de comunidades
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\RFC1156Agent"  -Name "sysServices" -Value 79 -PropertyType DWord
            # opcao 1  Public sem autorizacao 
            #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"  -Name "Public" -Value 1 -PropertyType DWord 
            # opcao 2  Public removido (habilitado)
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"  -Name "Public"
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"  -Name $communityName -Value 4 -PropertyType DWord   #1 None 2 notify 4 read only 8 read write 16 read create
    # fim da comfiguracao das comunidades

   # Configuracao dos hosts
   # Verificacao da ordem dos IPs e remocao do localhost - Mudancas profundas de registro devem ser feitas comparando arquivos .reg
   # Mesmo que na interface grafica os valores aparecam fora de ordem, no registro estarao ok!

    if ($key.GetValue($name, $null) -eq 'localhost') {  } else {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "1"  
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "1" -Value "172.31.102.7"  #counting up
    }
     if ($key.GetValue($name, $null) -eq '172.31.102.7') {  } else {
          Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "1"  
          New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "1" -Value "172.31.102.7"  #counting up
    }
    $name = '2' 
    if ($key.GetValue($name, $null) -eq '172.31.102.8') {  } else {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "2"  
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "2" -Value "172.31.102.8"  #counting up
    }
    $name = '3' 
    if ($key.GetValue($name, $null) -eq '172.31.102.10') {  } else {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "3"  
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"  -Name "3" -Value "172.31.102.10"  #counting up
    }
    # Fim da verificacao da ordem dos IPs e remocao do localhost
        
}
catch {
    Write-Host "Erro na configuracao do agente SNMP - verifique o arquivo de log criado" 
}

    Write-Host $Error | Out-File log.txt