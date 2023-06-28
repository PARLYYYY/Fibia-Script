function menu() 
{
    do
    {
        Clear-Host
        Write-Host -ForegroundColor cyan "
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                Fibia Bruger opret/nedlæg                 ┃
┃                                                          ┃
┃                                                          ┃
┃   1. Opret Intern bruger                                 ┃
┃   2. Opret Entreprenør bruger                            ┃
┃   3. Opret Konsulent bruger                              ┃
┃   4. Nedlæg Intern Bruger                                ┃
┃   5. Nedlæg Entreprenør bruger                           ┃
┃   6. Nedlæg Konsulent bruger                             ┃
┃                                                          ┃
┃   Ekstra                                                 ┃ 
┃                                                          ┃
┃   7. PowerShell versionen                                ┃
┃                                                          ┃
┃   0. Luk Script                                          ┃
┃                                                          ┃
┃                                                          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
            "
    #Nedenunder er menu strukturen opbygget med en switch function.
        $hovedmenu = read-host "Indtast valgmulighed 0-7"
    #Switchen har 5 functioner i sig 0-7 også har den en default som kører hvis der bliver valgt andet end  0-7.
        switch ($hovedmenu)
        {
            1 {Brugeroprettelse-intern}
            2 {Brugeroprettelse-Entreprenoer}
            3 {Brugeroprettelse-konsulent}
            4 {BrugerNedlaeggelse-intern}
            5 {BrugerNedlaeggelse-Entreprenoer}
            6 {BrugerNedlaeggelse-konsulent}
            ! {Hastenedlaeggelse}
     
            7 {PSVersion}

            0 {LukMenu}

            default 
            {
                Write-Host -ForegroundColor red "Forkert valgmulighed"
                sleep 2
            }
        }
    } until ($hovedmenu -eq 0)
}

    #Denne funktion indholder brugeroprettelse for interne bruger
function Brugeroprettelse-intern
{
    Write-Host "Denne function er ikke aktiv endnu"
    pause
}

    #Denne funktion indholder brugeroprettelse for entreprenoer bruger.
function Brugeroprettelse-Entreprenoer
{


   ################################################################################### Local AD #####################################################################################


    # Variabler med bruger og kopibruger som skal udfydelse under kørsel af scriptet.
    $Bruger = Read-Host "Indtast intialer på bruger som skal oprettes"
    $Kopibruger = read-host "Indtast intialer på den bruger som der skal kopires fra"
    $mobile = read-host "Indtast mobile nummer på bruger som skal oprettes"
    $Password = Read-host "Indtast password til bruger som skal oprettes"
    $Efternavn = Read-host "indtast efternavn på bruger som skal oprettes"
    $Description = Read-host "Indtast description på bruger"
    $Externmail = Read-host "Indtast externe mail på bruger"
    $Homefolder = "\\fibfil01.fibia.local\users\$Bruger"

    #Sætter password på bruger og enabler bruger.
    Set-ADAccountPassword -Identity $Bruger -Reset -NewPassword (ConvertTo-SecureString -String $Password -AsPlainText -Force)
    if (-not $Bruger.Enabled) {
        Enable-ADAccount -Identity $Bruger
    }


    #Finder liste med OU og viser dem i menu, så man kan vælge hvilken OU bruger skal flyttes til, bruger bliver efter valg flyttet.
    $OUListe = Get-ADOrganizationalUnit -SearchBase 'OU=Entreprenører,OU=FIBUsers,DC=fibia,DC=local' -Filter * | Select-Object Name
    $valgtOU = $OUListe | Out-GridView -Title "Vælg en OU, som brugeren skal flyttes til" -PassThru
    $valgtOU2 = $valgtOU.name
    Get-ADUser $Bruger | Move-ADObject -TargetPath "OU=$ValgtOU2,OU=Entreprenører,OU=FIBUsers,DC=fibia,DC=local"


    #Finder grupper på kopibruger og kopirer grupper til bruger som skal oprettes.
    $Kopigruppe = Get-ADPrincipalGroupMembership $Kopibruger | select Name
    foreach ($group in $Kopigruppe) {
        Add-ADGroupMember -Identity $group.Name -Members $Bruger
    }

    # Brug en switch til tilføje en bruger til koordinator eller tekniker grupper.
    CLS
    Write-Host "Vælg udfra om bruger er koordinator eller Tekniker:"
    Write-Host "1. Koordinator "
    Write-Host "2. Tekniker"

    $kordtekvalg = Read-Host "Indtast valg (1 eller 2)"


    switch ($kordtekvalg) {
    1 {
        # Tilføj brugeren til koordinator
        Add-ADGroupMember -Identity "ent_Koordinator_" -Members $Bruger
        Add-ADGroupMember -Identity "Entreprenør-koordinator" -Members $Bruger
        }
    2 {
        # Tilføj brugeren til tekniker
        Add-ADGroupMember -Identity "Ekstern Tekniker" -Members $Bruger
        Add-ADGroupMember -Identity "ent_teknikere_" -Members $Bruger
    }
    Default {
        # Hvis brugeren indtaster en ugyldig valgmulighed.
        Write-Host "Ugyldigt valg. Vælg enten 1 eller 2."
    }
}

    CLS
    $teamsharevalg = Read-Host "Vil du tilføje brugeren bruger til teamshare grupper? Skriv 'j' for ja eller 'n' for nej"

    if($teamsharevalg -eq "j"){
        Add-ADGroupMember -Identity Data_Teamshare_eksterne -Members $Bruger
        Add-ADGroupMember -Identity Data_Teamshare_Test_eksterne -Members $Bruger
    } elseif($teamsharevalg -eq "n"){
        Write-Host "Ingen ændringer blev foretaget."
    } 

    Pause

    CLS
    $vpnvalg = Read-Host "Vil du tilføje brugeren bruger til VPN gruppe? Skriv 'j' for ja eller 'n' for nej"

    if($vpnvalg -eq "j"){
        Add-ADGroupMember -Identity Fibia External VPN Access -Members $Bruger
    } elseif($vpnvalg -eq "n"){
        Write-Host "Ingen ændringer blev foretaget."
    } 

        Pause

    CLS
    $smallvalg = Read-Host "Vil du tilføje brugeren bruger til Smallmaps gruppe? Skriv 'j' for ja eller 'n' for nej"

    if($smallvalg -eq "j"){
        Add-ADGroupMember -Identity RDSUsersEnt  -Members $Bruger
    } elseif($smallvalg -eq "n"){
        Write-Host "Ingen ændringer blev foretaget."
    } 



    #Sætter mobile nummer på bruger
    Set-ADUser -Identity $Bruger -MobilePhone $Mobile
    #sætter Description på bruger
    Set-ADUser $Bruger -Description $Description
    #Sætter homefolder på bruger
    Set-ADUser $Bruger -HomeDrive "H:" -HomeDirectory $Homefolder
    #Sætter efternavn på bruger
    Set-ADUser $Bruger -Surname $Efternavn


    # Kopirer Job Titel, Company og Department fra kopibruger og sætter det på bruger som skal oprettes.
    $Kopibrugerobj = Get-ADUser $Kopibruger
    $Jobtitle = $Kopibrugerobj.Title
    $Department = $Kopibrugerobj.Department
    $Company = $Kopibrugerobj.Company
    Set-ADUser $Bruger -Title $Jobtitle -Department $Department -Company $Company


    #Forbinder til AAD sync server og syncer lokal AD til skyen.
    $AADComputer = "FIBDSY02.fibia.local"
    Write-Host -ForegroundColor Yellow "Forbinder til AAD Server, vent venligst."

    $AADConnect = New-PSSession -ComputerName $AADComputer -Authentication Kerberos
    Write-Host -ForegroundColor Yellow "Starting AAD Connect deltasync."
    Invoke-Command -Session $AADConnect -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $AADConnect -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Write-Host -ForegroundColor Yellow "AAD Connect deltasync er started. Der kan gå op til 5 minutter før syncen er komplet"
    pause
    Remove-PSSession $AADConnect


    ################################################################################# 0365 ########################################################################################


    #Forbinder til Azure Active Directory
    $Acc = "admincescom@fibia.dk"
    Import-module AzureAD
    Connect-AzureAD -Accountid $Acc


    #Lopper igennem grupper fra kopibruger og tilføjer dem til brugeren der blir oprettet. 
    $BrugerO365 = "$Bruger@fibia.dk"
    $KopibrugerO365 = "$Kopibruger@fibia.dk"
    $KopibrugerO365grupper = Get-AzureADUserMembership -ObjectId $KopibrugerO365.ObjectId
    foreach ($KopibrugerO365gruppe in $KopibrugerO365grupper) {
    $GrupperO365 = Get-AzureADGroup -ObjectId $KopibrugerO365gruppe.ObjectId
    Add-AzureADGroupMember -ObjectId $GrupperO365.ObjectId -RefObjectId $BrugerO365.ObjectId
    }

    # Disconnecter fra Azure AD
    Disconnect-AzureAD


    # forbinder til Exchange Online og laver en ny kontakt på brugeren.
    Import-moduel exchangeonlinemanagement
    Connect-ExchangeOnline -UserPrincipalName $Acc
    New-mailContact -Name "EXOC_$Bruger" -ExternalEmailAddress "$Externmail"

    #Disconnecter fra Exchange Online
    Disconnect-ExchangeOnline




    ############################################################################### Tidsreg paste ####################################################################################

    Clear
        Write-host -backgroundcolor red "  Copy/Paste nedeståenden ind i ticket til tidsregistring"
        Write-Host "
        
REKV: Service aftale

Følgende er gjort: 


Flyttet bruger til korrekt OU 

Tildelt grupper 

Tilføjet E-mail til AD konto 

Tilføjet Description 

Tilføjet Adresse, by og postnummer 

Tilføjet Mobiltelefonnummer jf. Sharepointlink 

Tilføjet Titel 

Tilføjet Afdeling 

Tilføjet Firma 

Tilføjet rettigheder jf. Sharepointlink 

Aktiveret brugeren 

Tilføjet Licenser 

Kørt ADSync 

Oprettet kontakt  

Tilføjet til distributionsliste 

Dokumentation af sag 

Sendt Mail til entreprenør"




}

    #Denne funktion indholder brugeroprettelse for Konsulent bruger.
function Brugeroprettelse-konsulent
{


   ################################################################################### Local AD #####################################################################################


    # Variabler med bruger og kopibruger som skal udfydelse under kørsel af scriptet.
    $Bruger = Read-Host "Indtast intialer på bruger som skal oprettes"
    $Kopibruger = read-host "Indtast intialer på den bruger som der skal kopires fra"
    $mobile = read-host "Indtast mobile nummer på bruger som skal oprettes"
    $Password = Read-host "Indtast password til bruger som skal oprettes"
    $Efternavn = Read-host "indtast efternavn på bruger som skal oprettes"
    $Description = "Ekstern konsulent"
    $Homefolder = "\\fibfil01.fibia.local\users\$Bruger"

    #Sætter password på bruger og enabler bruger.
    Set-ADAccountPassword -Identity $Bruger -Reset -NewPassword (ConvertTo-SecureString -String $Password -AsPlainText -Force)
    if (-not $Bruger.Enabled) {
        Enable-ADAccount -Identity $Bruger
    }


    #Finder liste med OU og viser dem i menu, så man kan vælge hvilken OU bruger skal flyttes til, bruger bliver efter valg flyttet.
    $OUListe = Get-ADOrganizationalUnit -SearchBase 'OU=Consultants,OU=FIBUsers,DC=fibia,DC=local' -Filter * | Select-Object Name
    $valgtOU = $OUListe | Out-GridView -Title "Vælg en OU, som brugeren skal flyttes til" -PassThru
    $valgtOU2 = $valgtOU.name
    Get-ADUser $Bruger | Move-ADObject -TargetPath "OU=$ValgtOU2,Consultants,OU=FIBUsers,DC=fibia,DC=local"


    #Finder grupper på kopibruger og kopirer grupper til bruger som skal oprettes.
    $Kopigruppe = Get-ADPrincipalGroupMembership $Kopibruger | select Name
    foreach ($group in $Kopigruppe) {
        Add-ADGroupMember -Identity $group.Name -Members $Bruger
    }


    #Sætter mobile nummer på bruger
    Set-ADUser -Identity $Bruger -MobilePhone $Mobile
    #sætter Description på bruger
    Set-ADUser $Bruger -Description $Description
    #Sætter homefolder på bruger
    Set-ADUser $Bruger -HomeDrive "H:" -HomeDirectory $Homefolder
    #Sætter efternavn på bruger
    Set-ADUser $Bruger -Surname $Efternavn


    # Kopirer Job Titel, Company og Department fra kopibruger og sætter det på bruger som skal oprettes.
    $Kopibrugerobj = Get-ADUser $Kopibruger
    $Jobtitle = $Kopibrugerobj.Title
    $Department = $Kopibrugerobj.Department
    $Company = $Kopibrugerobj.Company
    Set-ADUser $Bruger -Title $Jobtitle -Department $Department -Company $Company


    #Forbinder til AAD sync server og syncer lokal AD til skyen.
    $AADComputer = "FIBDSY02.fibia.local"
    Write-Host -ForegroundColor Yellow "Forbinder til AAD Server, vent venligst."

    $AADConnect = New-PSSession -ComputerName $AADComputer -Authentication Kerberos
    Write-Host -ForegroundColor Yellow "Starting AAD Connect deltasync."
    Invoke-Command -Session $AADConnect -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $AADConnect -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Write-Host -ForegroundColor Yellow "AAD Connect deltasync er started. Der kan gå op til 5 minutter før syncen er komplet"
    pause
    Remove-PSSession $AADConnect


    ################################################################################# 0365 ########################################################################################


    #Forbinder til Azure Active Directory
    $Acc = "admincescom@fibia.dk"
    Import-module AzureAD
    Connect-AzureAD -Accountid $Acc

# Looper igennem kopibrugers grupper og tilføjer dem til bruger som skal oprettes.
    $BrugerO365 = "$Bruger@fibia.dk"
    $KopibrugerO365 = "$Kopibruger@fibia.dk"
    $KopibrugerO365grupper = Get-AzureADUserMembership -ObjectId $KopibrugerO365.ObjectId
    foreach ($KopibrugerO365gruppe in $KopibrugerO365grupper) {
    $GrupperO365 = Get-AzureADGroup -ObjectId $KopibrugerO365gruppe.ObjectId
    Add-AzureADGroupMember -ObjectId $GrupperO365.ObjectId -RefObjectId $BrugerO365.ObjectId
    }

# Disconnecter fra Azure AD
Disconnect-AzureAD


    ############################################################################### Tidsreg paste ####################################################################################

    clear
    Write-host -backgroundcolor Red "Send Mail til konsulent med logon oplysninger. - Bestiller af bruger, skal på CC på mailen."
    Pause

    Clear
        Write-host -backgroundcolor red "Copy/Paste nedeståenden ind i ticket til tidsregistring"
        Write-Host "
        
REKV: Service aftale

Følgende er gjort: 

Flyttet bruger til korrekt OU 

Tildelt grupper 

Tilføjet E-mail til AD konto 

Tilføjet Description 

Tilføjet Adresse, by og postnummer 

Tilføjet Homefolder 

Tilføjet Mobiltelefonnummer jf. Sharepointlink 

Tilføjet Titel 

Tilføjet Afdeling 

Tilføjet Firma 

Tilføjet Leder 

Aktiveret brugeren 

Tilføjet Licenser 

Kørt ADSync 

Sendt mail til konsulenten med login 

Dokumentation af sag 

Sag lukket "

Pause

}

    #Denne funktion indholder brugernedlæggelse for intern bruger. 
function BrugerNedlaeggelse-intern
{
    

    ################################################################################### Local AD #####################################################################################


    #Variabler der skal udfyldes
    Clear
    $bruger = read-Host "Skriv UPN på den bruger der skal nedlægges(Kun deres intialer)"
    clear
    $CSD = read-host "Indtast CSD Nummer(Kun tal)"
    clear
    #Disabler bruger i AD
    Disable-ADAccount -identity $Bruger

    #Ændre Msexchhidefromaddresslists til true i atribut editor.
    get-aduser -identity $Bruger | Set-ADObject -Replace @{msExchHideFromAddressLists=$true}

    #Fjerner indhold i msRTCDeploymentlocator i atribut editor.
    get-aduser -identity $Bruger | Set-ADUser -Clear msRTCSIP-DeploymentLocator

    #Fjerner indhold i msRTCSipline i atribut editor.
    get-aduser -identity $Bruger | Set-ADUser -Clear msRTCSip-line

    #Ændre description til "Bruger lukket DD/MM/YYYY - CSD-xxxxxxx"
    $dato = get-date -format "dd/MM/yyyy"
    Set-ADUser $bruger -Description "bruger lukket $dato - CSD-$CSD"

    #Fjerner alle grupper på bruger undtagen "Domain users"
    Get-AdPrincipalGroupMembership -Identity $bruger | Where-Object -Property Name -Ne -Value 'Domain Users' | Remove-AdGroupMember -Members $bruger  -confirm

    #Generer random password til password reset
    function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $laengde,
        [int] $Ikkealphabetisc = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($laengde, $Ikkealphabetisc)
    }
    $password = Get-RandomPassword 20

    #Sætter random genereret password på bruger.
    set-adaccountpassword -identity $bruger -newpassword (ConvertTo-SecureString -AsPlainText -Force $password)

    #Fjerner Telefonnummer og mail på bruger
    Set-ADUser -Identity $bruger -Clear mobile
    Set-ADUser -Identity $bruger -Clear HomePhone
    Set-ADuser -identity $bruger -clear pager
    Set-ADuser -identity $bruger -clear mail

    #Ændre navn på bruger
    $Navn = get-aduser -Identity $bruger | select name
    $fuldenavn = "fratrådt_" + $Navn.name
    set-aduser -Identity $bruger -displayname $fuldenavn
    Get-ADUser -identity $bruger | Rename-ADObject -NewName $fuldenavn

    #Dynamisk defination af OU's Navn
    $AAr = get-date -format yyyy
    $MM = get-date -format MM
    $MMtext = (Get-Culture).DateTimeFormat.GetMonthName($MM)
    $ounavn = "$AAr $MM $MMtext"

    #Flytter bruger til korrekt OU
    Get-ADuser -identity $bruger | Move-ADObject -targetpath "OU=$ounavn,OU=Disabled Users,OU=FIBUsers,DC=Fibia,DC=LOCAL" -confirm


    #Forbinder til AAD sync server og syncer lokal AD til skyen.
    $AADComputer = "FIBDSY02.fibia.local"
    Write-Host -ForegroundColor Yellow "Forbinder til AAD Server, vent venligst."

    $AADConnect = New-PSSession -ComputerName $AADComputer -Authentication Kerberos
    Write-Host -ForegroundColor Yellow "Starting AAD Connect deltasync."
    Invoke-Command -Session $AADConnect -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $AADConnect -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Write-Host -ForegroundColor Yellow "AAD Connect deltasync er started. Der kan gå op til 5 minutter før syncen er komplet"
    pause
    Remove-PSSession $AADConnect


    ################################################################################# 0365 ########################################################################################
    

    $Acc = "admincescom@fibia.dk"


    #Forbinder til Azure Active Directory
    Connect-AzureAD -Accountid $Acc

    #Forbinder til Exchange Online
    Install-Module ExchangeOnlineManagement
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -UserPrincipalName $Acc

    $brugerO365 = "$bruger@fibia.dk"

        #Fjerner licenser hvis der er nogen.
    $AssignedLicenses = (Get-AzureADUser -ObjectId $brugerO365).AssignedLicenses
    If ($AssignedLicenses.Count -gt 0)
    {
        Connect-MsolService 
        (get-MsolUser -UserPrincipalName $brugerO365).licenses.AccountSkuId |
            foreach{
            Set-MsolUserLicense -UserPrincipalName $brugerO365 -RemoveLicenses $_ -erroraction SilentlyContinue
            }
    }

    #Sætter Autosvar
    Set-MailboxAutoReplyConfiguration -Identity $brugerO365 -AutoReplyState Enabled -InternalMessage "
Denne mailkonto er ikke længere aktiv.
Kontakt venligst: 
Fibia
Tlf: 70 29 24 44" -ExternalMessage "
Denne mailkonto er ikke længere aktiv.
Kontakt venligst: 
Fibia
Tlf: 70 29 24 44 
" -ExternalAudience All


    #Fjerner Azure Grupper fra Bruger
    $brugerid = (Get-AzureADuser -objectid $brugerO365).objectid
    $grupper = Get-AzureADUserMembership -ObjectId $brugerID 
    foreach($Group in $grupper){ 
        try { 
        Remove-AzureADGroupMember -ObjectId $Group.ObjectID -MemberId $brugerID -ErrorAction SilentlyContinue
            }
        catch {
        write-host "$($Group.displayname) membership cannot be removed via Azure cmdlets."
        Remove-DistributionGroupMember -identity $Group.mail -member $brugerid -BypassSecurityGroupManagerCheck -ErrorAction SilentlyContinue
              }
}
        #Konverter til Shared Mailbox
    Set-Mailbox "$brugerO365" -Type Shared -ErrorAction SilentlyContinue

    ############################################################################# Verificering #######################################################################################

    
        CLS
        Write-host -BackgroundColor Red "!!!!!!!! Hvis nogen af nedestående felter er røde, skal det tjekkes manuelt(Tjek eventuelt guide) !!!!!!!!"

    #Verificering af om bruger er disabled.
        $EnabledStatus = Get-ADUser -identity $bruger -Properties *| Select Enabled
    if ($EnabledStatus.Enabled -eq $true)
        {
        Write-host -foregroundcolor Red " - AD Account er ikke disabled"
        }
    Else
        {
        Write-host -foregroundcolor Green " - AD Account er disabled"
        }
        
    #Verificering af Description på bruger.
        $Descget = get-ADUser -identity $bruger -properties Description | select Description
        $DescEQ = "Bruger lukket $dato - CSD-$csd"
    if ($DescEQ -eq $Descget.Description)
        {
        Write-host -foregroundcolor Green " - Description er korrekt sat på lukket bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Description er ikke sat på bruger"
        }
    
    #Verificering af msExchHideFromAddressLists på bruger.
        $Hidefromaddress = Get-ADUser -identity $bruger -Properties msExchHideFromAddressLists | Select msExchHideFromAddressLists
        $HidefromaddressEQ = "True"
    if ($HidefromaddressEQ -ne $Hidefromaddress.msExchHideFromAddressLists)
        {
        Write-host -foregroundcolor Red " - msExchHideFromAddressLists er ikke sat til True på bruger"
        }
    Else
        {
        Write-host -foregroundcolor Green " - msExchHideFromAddressLists er sat til True på bruger"
        }
       
    #Verificering af brugers placring i OU
    if (Get-ADUser -Filter "SamAccountName -eq '$bruger'" -SearchBase "OU=$ounavn,OU=Disabled Users,OU=FIBUsers,DC=Fibia,DC=LOCAL")
        {
        Write-host -foregroundcolor Green " - Bruger er i korrekt OU"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Bruger er i forkerte OU"
        }
        
    #Verificering af fjernelse af ON prem sikkerhedsgrupper
        $Grupperveri = Get-AdPrincipalGroupMembership -Identity $bruger | select name
        $GrupperveriEQ = "Domain Users"

    if ($GrupperveriEQ -match $Grupperveri.name)
        {
        Write-host -foregroundcolor Green " - Alle grupper er fjernet fra bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Alle grupper er ikke fjernet fra bruger "
        }
    
    #verificering af password reset
        $Passwordlastchange = get-aduser -Identity $bruger -properties PasswordLastSet | select @{Name='LastPasswordChangeDate';Expression={($_.PasswordLastSet).toString("dd/MM/yyyy")}}
        $PasswordlastchangeEQ = Get-Date -Format dd/MM/yyyy
    if ($Passwordlastchange.LastPasswordChangeDate -match $PasswordlastchangeEQ)
        {
        Write-host -foregroundcolor Green " - Password er resettet på bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Password er ikke resettet på bruger"
        }
        
    #Verificering af Præfiks (Fratrådt_) er sat på bruger
        $prefix = Get-Aduser -Identity $bruger | select name
        $prefixEQ = "fratrådt_*"
    if ($prefix.name -match $prefixEQ)
        {
        Write-host -foregroundcolor Green " - 'Fratrådt' prefix er påsat brugers navn"
        }
    Else
        {
        Write-host -foregroundcolor Red " - 'Fratrådt' prefix er ikke påsat brugers navn"
        }
       
    #Verificering af Mail og telephone er fjernet
        $TjekTLF = Get-ADUser -Identity $bruger -Property mobile, homephone, pager, mail | Select mobile, homephone, pager, mail
    if($TjekTLF.mobile -eq $NULL -and $TjekTLF.pager -eq $NULL -and $TjekTLF.homephone -eq $NULL -and $TjekTLF.mail -eq $NULL)
        {
    Write-Host -ForegroundColor Green " - Bruger har fået fjernet Mail, Mobile, Pager og Homephone"
        }
    else
        {
        Write-Host -ForegroundColor red " - Bruger har ikke fået fjernet Mail, Mobile, Pager og Homephone"
        }

     #Verificering af msRTCDeploymentlocator er fjernet.
    $TjekmsRTC = Get-ADUser -Identity $bruger -Property msRTCSIP-Deploymentlocator | Select msRTCSIPDeploymentlocator
    if($TjekmsRTC.msRTCSIPDeploymentlocator -eq $NULL)
        {
    Write-Host -ForegroundColor Green " - Bruger har fået fjernet indhold i msRTCDeploymentlocator"
        }
    else
        {
        Write-Host -ForegroundColor red " - Bruger har ikke fået fjernet indhold i msRTCDeploymentlocator"
        }
    #Verificering af msRTCSipline er fjernet
    $TjekmsRTCSipline = Get-ADUser -Identity $bruger -Property msRTCSIP-line | Select msRTCSIPline
    if($TjekmsRTCSipline.msRTCSIPline -eq $NULL)
        {
    Write-Host -ForegroundColor Green " - Bruger har fået fjernet indhold i msRTCSipline"
        }
    else
        {
        Write-Host -ForegroundColor red " - Bruger har ikke fået fjernet indhold i msRTCSipline"
        }

        pause


    ############################################################################### Tidsreg paste ####################################################################################


        clear
        $Dag = get-date -Format dd

        Write-host -backgroundcolor red "  Copy/Paste nedeståenden ind i ticket til tidsregistring"
        Write-Host 
        "
    REKV: Service Aftale

•	Nedlæggelse af bruger $bruger@fibia.dk
•	Tilføjet Bruger lukket $Dag-$MM-2023 - CSD-$CSD i description på brugerens AD konto
•	Opsat autosvar (se Powershell script Autoreply) Connect-exchangeonline først i Powershell 
•	Konverteret postkasse til Delt Postkasse (se Powershell script Shared mailbox) set-mailbox -Identity sibbr@fibia.dk -type Shared 
•	Reset password i on-premises Active Directory 
•	Deaktiveret bruger i on-premises Active Directory 
•	Fjernet bruger fra on-premise Active Directory sikkerhedsgrupper 
•	Omdøbt bruger med præfiks med Fratrådt_ 
•	Fjernet postkasse fra distributionslister i Exchange admin center 
•	Flyttet  bruger til OU fibia.local/FIBUsers/Disabled Users/<Årstal  månedsnummer månedsnedsnavn> (opret OU hvis den ikke findes) 
•	Sat msExchHideFromAddressLists til TRUE i Attribute Editor I on-premises Active Directory 
•	Sat Proxyaddresses til enkelt SMTP i Attribute Editor I on-premises Active Directory 
•	Kontrol af MailNickname i Attribute Editor I on-premises Active Directory 
•	Fjernet bruger fra Azure sikkerhedsgrupper Azure Active Directory admin center 
•	Fjernet virksomhedsdata fra brugerens Active devices i  Microsoft 365 admin center - Logget på O365 som GlobalAdmin, 
    Gået til EndPoint Manager, Fundet brugeren. Valgt Devices: Wipe 

•	Frigjort Teams telefonnummer fra bruger – Logget på O365, tilgået Microsoft Teams Administration - fjernet Teams tlfnummer fra bruger i AD 
•	igangsat manuel sync med AAD Connect 
•	Fjernet Office 365 licenser fra brugeren i Microsoft 365 admin center 
•	kontrolleret at brugeren er blokeret og præfiks er synligt efter manuel sync med AAD Connect
•	Send mail til itsupportoest@fibia.dk
•	Vinget opgave udført i Sharepoint Link  
•	Send mail til Suras@fibia.dk
"
        pause


}

    #Denne funktion indholder brugernedlæggelse for Entreprenoer bruger. 
function BrugerNedlaeggelse-Entreprenoer
{


#################################################################################### Local AD ########################################################################################


    #Variabler der skal udfyldes
    Clear
    $bruger = read-Host "Skriv UPN på den bruger der skal nedlægges(Kun 'Ent_xxx')"
    clear
    $CSD = read-host "Indtast CSD Nummer(Kun tal)"
    clear
    #Disabler bruger i AD
    Disable-ADAccount -identity $Bruger

    #Ændre Msexchhidefromaddresslists til true i atribbut editor.
    get-aduser -identity $Bruger | Set-ADObject -Replace @{msExchHideFromAddressLists=$true}

    #Ændre description til "Bruger lukket DD/MM/YYYY - CSD-xxxxxxx"
    $dato = get-date -format "dd/MM/yyyy"
    Set-ADUser $bruger -Description "bruger lukket $dato - CSD-$CSD"

    #Fjerner alle grupper på bruger undtagen "Domain users"
    Get-AdPrincipalGroupMembership -Identity $bruger | Where-Object -Property Name -Ne -Value 'Domain Users' | Remove-AdGroupMember -Members $bruger -confirm

    #Generer random password til password reset
    function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $laengde,
        [int] $Ikkealphabetisc = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($laengde, $Ikkealphabetisc)
    }
    $password = Get-RandomPassword 20

    #Sætter random genereret password på bruger.
    set-adaccountpassword -identity $bruger -newpassword (ConvertTo-SecureString -AsPlainText -Force $password)

    #Fjerner Telefonnummer og mail på bruger
    Set-ADUser -Identity $bruger -Clear mobile
    Set-ADUser -Identity $bruger -Clear HomePhone
    Set-ADuser -identity $bruger -clear pager
    Set-ADuser -identity $bruger -clear mail

    #Ændre navn på bruger
    $Navn = get-aduser -Identity $bruger | select name
    $fuldenavn = "fratrådt_" + $Navn.name
    set-aduser -Identity $bruger -displayname $fuldenavn
    Get-ADUser -identity $bruger | Rename-ADObject -NewName $fuldenavn

    #Dynamisk defination af OU's Navn
    $AAr = get-date -format yyyy
    $MM = get-date -format MM
    $MMtext = (Get-Culture).DateTimeFormat.GetMonthName($MM)
    $ounavn = "$AAr $MM $MMtext"

    #Flytter bruger til korrekt OU
    Get-ADuser -identity $bruger | Move-ADObject -targetpath "OU=$ounavn,OU=Disabled Users,OU=FIBUsers,DC=Fibia,DC=LOCAL"

    #Forbinder til AAD sync server og syncer lokal AD til skyen.
    $AADComputer = "FIBDSY02.fibia.local"
    Write-Host -ForegroundColor Yellow "Forbinder til AAD Server, vent venligst."

    $AADConnect = New-PSSession -ComputerName $AADComputer -Authentication Kerberos
    Write-Host -ForegroundColor Yellow "Starting AAD Connect deltasync."
    Invoke-Command -Session $AADConnect -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $AADConnect -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Write-Host -ForegroundColor Yellow "AAD Connect deltasync er started. Der kan gå op til 5 minutter før syncen er komplet"
    pause
    Remove-PSSession $AADConnect


##################################################################################### 0365 ###########################################################################################
    

    $Acc = "admincescom@fibia.dk"


    #Forbinder til Azure Active Directory
    Connect-AzureAD -Accountid $Acc

    #Forbinder til Exchange Online
    Install-Module ExchangeOnlineManagement -Confirm
    Import-Module ExchangeOnlineManagement -PassThru
    Connect-ExchangeOnline -UserPrincipalName $Acc

    $brugerO365 = "$bruger@fibia.dk"

    #Fjerner licenser hvis der er nogen.
    $AssignedLicenses = (Get-AzureADUser -ObjectId $brugerO365).AssignedLicenses
    If ($AssignedLicenses.Count -gt 0)
    {
        Connect-MsolService
        (get-MsolUser -UserPrincipalName $brugerO365).licenses.AccountSkuId |
        foreach{
        Set-MsolUserLicense -UserPrincipalName $brugerO365 -RemoveLicenses $_
        }
    }

    #Sætter Autosvar
    Set-MailboxAutoReplyConfiguration -Identity $brugerO365 -AutoReplyState Enabled -InternalMessage "
Denne mailkonto er ikke længere aktiv.
Kontakt venligst: 
Fibia
Tlf: 70 29 24 44" -ExternalMessage "
Denne mailkonto er ikke længere aktiv.
Kontakt venligst: 
Fibia
Tlf: 70 29 24 44 
" -ExternalAudience All


    #Fjerner Azure Grupper fra Bruger
    $brugerid = (Get-AzureADuser -objectid $brugerO365).objectid
    $grupper = Get-AzureADUserMembership -ObjectId $brugerID 
    foreach($Group in $grupper){ 
        try { 
        Remove-AzureADGroupMember -ObjectId $Group.ObjectID -MemberId $brugerID -ErrorAction SilentlyContinue
            }
        catch {
        write-host "$($Group.displayname) membership cannot be removed via Azure cmdlets."
        Remove-DistributionGroupMember -identity $Group.mail -member $brugerid -BypassSecurityGroupManagerCheck -ErrorAction SilentlyContinue
              }
}

    #Konverter til Shared Mailbox
    Set-Mailbox "$brugerO365" -Type Shared -ErrorAction SilentlyContinue

############################################################################### Verificering #########################################################################################

    
        CLS
        Write-host -BackgroundColor Red "!!!!!!!! Hvis nogen af nedestående felter er røde, skal det tjekkes manuelt(Tjek eventuelt guide) !!!!!!!!"

    #Verificering af om bruger er disabled.
        $EnabledStatus = Get-ADUser -identity $bruger -Properties *| Select Enabled
    if ($EnabledStatus.Enabled -eq $true)
        {
        Write-host -foregroundcolor Red " - AD Account er ikke disabled"
        }
    Else
        {
        Write-host -foregroundcolor Green " - AD Account er disabled"
        }
        
    #Verificering af Description på bruger.
        $Descget = get-ADUser -identity $bruger -properties Description | select Description
        $DescEQ = "Bruger lukket $dato - CSD-$csd"
    if ($DescEQ -eq $Descget.Description)
        {
        Write-host -foregroundcolor Green " - Description er korrekt sat på lukket bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Description er ikke sat på bruger"
        }
    
    #Verificering af msExchHideFromAddressLists på bruger.
        $Hidefromaddress = Get-ADUser -identity $bruger -Properties msExchHideFromAddressLists | Select msExchHideFromAddressLists
        $HidefromaddressEQ = "True"
    if ($HidefromaddressEQ -ne $Hidefromaddress.msExchHideFromAddressLists)
        {
        Write-host -foregroundcolor Red " - msExchHideFromAddressLists er ikke sat til True på bruger"
        }
    Else
        {
        Write-host -foregroundcolor Green " - msExchHideFromAddressLists er sat til True på bruger"
        }
       
    #Verificering af brugers placring i OU
    if (Get-ADUser -Filter "SamAccountName -eq '$bruger'" -SearchBase "OU=$ounavn,OU=Disabled Users,OU=FIBUsers,DC=Fibia,DC=LOCAL")
        {
        Write-host -foregroundcolor Green " - Bruger er i korrekt OU"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Bruger er i forkerte OU"
        }
        
    #Verificering af fjernelse af ON prem sikkerhedsgrupper
        $Grupperveri = Get-AdPrincipalGroupMembership -Identity $bruger | select name
        $GrupperveriEQ = "Domain Users"

    if ($GrupperveriEQ -match $Grupperveri.name)
        {
        Write-host -foregroundcolor Green " - Alle grupper er fjernet fra bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Alle grupper er ikke fjernet fra bruger "
        }
    
    #verificering af password reset
        $Passwordlastchange = get-aduser -Identity $bruger -properties PasswordLastSet | select @{Name='LastPasswordChangeDate';Expression={($_.PasswordLastSet).toString("dd/MM/yyyy")}}
        $PasswordlastchangeEQ = Get-Date -Format dd/MM/yyyy
    if ($Passwordlastchange.LastPasswordChangeDate -match $PasswordlastchangeEQ)
        {
        Write-host -foregroundcolor Green " - Password er resettet på bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Password er ikke resettet på bruger"
        }
        
    #Verificering af Præfiks (Fratrådt_) er sat på bruger
        $prefix = Get-Aduser -Identity $bruger | select name
        $prefixEQ = "fratrådt_*"
    if ($prefix.name -match $prefixEQ)
        {
        Write-host -foregroundcolor Green " - 'Fratrådt' prefix er påsat brugers navn"
        }
    Else
        {
        Write-host -foregroundcolor Red " - 'Fratrådt' prefix er ikke påsat brugers navn"
        }
       
    #Verificering af Mail og telephone er fjernet
        $TjekTLF = Get-ADUser -Identity $bruger -Property mobile, homephone, pager, mail | Select mobile, homephone, pager, mail
    if($TjekTLF.mobile -eq $NULL -and $TjekTLF.pager -eq $NULL -and $TjekTLF.homephone -eq $NULL -and $TjekTLF.mail -eq $NULL)
        {
    Write-Host -ForegroundColor Green " - Bruger har fået fjernet Mail, Mobile, Pager og Homephone"
        }
    else
        {
        Write-Host -ForegroundColor red " - Bruger har ikke fået fjernet Mail, Mobile, Pager og Homephone"
        }
        pause


################################################################################# Tidsreg paste ######################################################################################


        clear
        $Dag = get-date -Format dd

        Write-host -backgroundcolor red "  Copy/Paste nedeståenden ind i ticket til tidsregistring"
        Write-Host 
        "
    REKV: Service Aftale

•	Nedlæggelse af bruger $bruger@fibia.dk
•	Tilføjet Bruger lukket $Dag-$MM-2023 - CSD-$CSD i description på brugerens AD konto
•	Verificeret at brugeren har en postkasse i Fibia - Hvis brugeren har en postkasse, følg exchange steps i guide
•	Tilføjet autosvar i postkasse
•	Konverteret postkasse til Delt Postkasse
•	Verificeret at brugeren ikke har Microsoft Teams nummer (fjernet)
•	Reset password i on-premises Active Directory
•	Deaktiver bruger i on-premises Active Directory
•	Fjernet Office 365 licenser fra brugeren i Microsoft 365 admin center
•	Flyt bruger til OU
•	Fjernet bruger fra on-premise Active Directory sikkerhedsgrupper
•	Fjernet Email fra brugeren i Active Direcotory 
•	Fjernet Telefonnummer i fanen Telephones 
•	Fjernet bruger fra Azure sikkerhedsgrupper Azure Active Directory admin center 
•	Fjernet bruger fra distributionsliste
•	Omdøb bruger med præfiks med Fratrådt_ og ændre display name på brugeren
•	Sat msExchHideFromAddressLists til TRUE i Attribute Editor I on-premises Active Directory
•	Sat Proxyaddresses til enkelt SMTP i Attribute Editor I on-premises Active Directory
•	Kontrol af MailNickname i Attribute Editor I on-premises Active Directory
•	igangsat manuel sync med AAD Connect
•	kontrolleret at brugeren er blokeret og præfiks er synligt efter manuel sync med AAD Connect
•	Sendt mail til itsupportoest@fibia vedr. lukning 
•	Vinget opgave udført i Sharepoint Link
•	Send mail til ler@fibia.dk vedr. lukning
"
        pause
}

    #Denne funktion indholder brugernedlæggelse for Konsulent bruger.
function BrugerNedlaeggelse-konsulent
{


    ################################################################################### Local AD #####################################################################################


    #Variabler der skal udfyldes
    Clear
    $bruger = read-Host "Skriv UPN på den bruger der skal nedlægges(Kun 'Ent_xxx')"
    clear
    $CSD = read-host "Indtast CSD Nummer(Kun tal)"
    clear
    #Disabler bruger i AD
    Disable-ADAccount -identity $Bruger

    #Ændre Msexchhidefromaddresslists til true i atribbut editor.
    get-aduser -identity $Bruger | Set-ADObject -Replace @{msExchHideFromAddressLists=$true}

    #Ændre description til "Bruger lukket DD/MM/YYYY - CSD-xxxxxxx"
    $dato = get-date -format "dd/MM/yyyy"
    Set-ADUser $bruger -Description "bruger lukket $dato - CSD-$CSD"

    #Fjerner alle grupper på bruger undtagen "Domain users"
    Get-AdPrincipalGroupMembership -Identity $bruger | Where-Object -Property Name -Ne -Value 'Domain Users' | Remove-AdGroupMember -Members $bruger -confirm

    #Generer random password til password reset
    function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $laengde,
        [int] $Ikkealphabetisc = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($laengde, $Ikkealphabetisc)
    }
    $password = Get-RandomPassword 20

    #Sætter random genereret password på bruger.
    set-adaccountpassword -identity $bruger -newpassword (ConvertTo-SecureString -AsPlainText -Force $password)

    #Fjerner Telefonnummer og mail på bruger
    Set-ADUser -Identity $bruger -Clear mobile
    Set-ADUser -Identity $bruger -Clear HomePhone
    Set-ADuser -identity $bruger -clear pager
    Set-ADuser -identity $bruger -clear mail

    #Ændre navn på bruger
    $Navn = get-aduser -Identity $bruger | select name
    $fuldenavn = "fratrådt_" + $Navn.name
    set-aduser -Identity $bruger -displayname $fuldenavn
    Get-ADUser -identity $bruger | Rename-ADObject -NewName $fuldenavn

    #Dynamisk defination af OU's Navn
    $AAr = get-date -format yyyy
    $MM = get-date -format MM
    $MMtext = (Get-Culture).DateTimeFormat.GetMonthName($MM)

    $ounavn = "$AAr $MM $MMtext"

    #Flytter bruger til korrekt OU
    Get-ADuser -identity $bruger | Move-ADObject -targetpath "OU=$ounavn,OU=Disabled Users,OU=FIBUsers,DC=Fibia,DC=LOCAL"

    #Forbinder til AAD sync server og syncer lokal AD til skyen.
    $AADComputer = "FIBDSY02.fibia.local"
    Write-Host -ForegroundColor Yellow "Forbinder til AAD Server, vent venligst."

    $AADConnect = New-PSSession -ComputerName $AADComputer -Authentication Kerberos
    Write-Host -ForegroundColor Yellow "Starting AAD Connect deltasync."
    Invoke-Command -Session $AADConnect -ScriptBlock {Import-Module -Name 'ADSync'}
    Invoke-Command -Session $AADConnect -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
    Write-Host -ForegroundColor Yellow "AAD Connect deltasync er started. Der kan gå op til 5 minutter før syncen er komplet"
    pause
    Remove-PSSession $AADConnect


    ################################################################################# 0365 ########################################################################################
    
   
    $Acc = "admincescom@fibia.dk"

    #Forbinder til Azure Active Directory
    Connect-AzureAD -Accountid $Acc

    #Forbinder til Exchange Online
    Install-Module ExchangeOnlineManagement
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -UserPrincipalName $Acc

    $brugerO365 = "$bruger@fibia.dk"

    #Fjerner licenser hvis der er nogen.
    $AssignedLicenses = (Get-AzureADUser -ObjectId $brugerO365).AssignedLicenses
    If ($AssignedLicenses.Count -gt 0)
    {
        Connect-MsolService
        (get-MsolUser -UserPrincipalName $brugerO365).licenses.AccountSkuId |
        foreach{
        Set-MsolUserLicense -UserPrincipalName $brugerO365 -RemoveLicenses $_
        }
    }

    #Sætter Autosvar
    Set-MailboxAutoReplyConfiguration -Identity $brugerO365 -AutoReplyState Enabled -InternalMessage "
Denne mailkonto er ikke længere aktiv.
Kontakt venligst: 
Fibia
Tlf: 70 29 24 44" -ExternalMessage "
Denne mailkonto er ikke længere aktiv.
Kontakt venligst: 
Fibia
Tlf: 70 29 24 44 
" -ExternalAudience All

    #Fjerner Azure Grupper fra Bruger
    $brugerid = (Get-AzureADuser -objectid $brugerO365).objectid
    $grupper = Get-AzureADUserMembership -ObjectId $brugerID 
    foreach($Group in $grupper){ 
        try { 
        Remove-AzureADGroupMember -ObjectId $Group.ObjectID -MemberId $brugerID -ErrorAction SilentlyContinue
            }
        catch {
        write-host "$($Group.displayname) membership cannot be removed via Azure cmdlets."
        Remove-DistributionGroupMember -identity $Group.mail -member $brugerid -BypassSecurityGroupManagerCheck -ErrorAction SilentlyContinue
              }
}

    #Konverter til Shared Mailbox
    Set-Mailbox "$brugerO365" -Type Shared -ErrorAction SilentlyContinue

    ############################################################################# Verificering #######################################################################################

    
        CLS
        Write-host -BackgroundColor Red "!!!!!!!! Hvis nogen af nedestående felter er røde, skal det tjekkes manuelt(Tjek eventuelt guide) !!!!!!!!"

        #Verificering af om bruger er disabled.
        $EnabledStatus = Get-ADUser -identity $bruger -Properties *| Select Enabled
    if ($EnabledStatus.Enabled -eq $true)
        {
        Write-host -foregroundcolor Red " - AD Account er ikke disabled"
        }
    Else
        {
        Write-host -foregroundcolor Green " - AD Account er disabled"
        }
        
    #Verificering af Description på bruger.
        $Descget = get-ADUser -identity $bruger -properties Description | select Description
        $DescEQ = "Bruger lukket $dato - CSD-$csd"

    if ($DescEQ -eq $Descget.Description)
        {
        Write-host -foregroundcolor Green " - Description er korrekt sat på lukket bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Description er ikke sat på bruger"
        }
    
    #Verificering af msExchHideFromAddressLists på bruger.
        $Hidefromaddress = Get-ADUser -identity $bruger -Properties msExchHideFromAddressLists | Select msExchHideFromAddressLists
        $HidefromaddressEQ = "True"
    if ($HidefromaddressEQ -ne $Hidefromaddress.msExchHideFromAddressLists)
        {
        Write-host -foregroundcolor Red " - msExchHideFromAddressLists er ikke sat til True på bruger"
        }
    Else
        {
        Write-host -foregroundcolor Green " - msExchHideFromAddressLists er sat til True på bruger"
        }
       
    #Verificering af brugers placring i OU
    if (Get-ADUser -Filter "SamAccountName -eq '$bruger'" -SearchBase "OU=$ounavn,OU=Disabled Users,OU=FIBUsers,DC=Fibia,DC=LOCAL")
        {
        Write-host -foregroundcolor Green " - Bruger er i korrekt OU"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Bruger er i forkerte OU"
        }
        
    #Verificering af fjernelse af ON prem sikkerhedsgrupper
        $Grupperveri = Get-AdPrincipalGroupMembership -Identity $bruger | select name
        $GrupperveriEQ = "Domain Users"

    if ($GrupperveriEQ -match $Grupperveri.name)
        {
        Write-host -foregroundcolor Green " - Alle grupper er fjernet fra bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Alle grupper er ikke fjernet fra bruger "
        }
    
    #verificering af password reset
        $Passwordlastchange = get-aduser -Identity $bruger -properties PasswordLastSet | select @{Name='LastPasswordChangeDate';Expression={($_.PasswordLastSet).toString("dd/MM/yyyy")}}
        $PasswordlastchangeEQ = Get-Date -Format dd/MM/yyyy
        

    if ($Passwordlastchange.LastPasswordChangeDate -match $PasswordlastchangeEQ)
        {
        Write-host -foregroundcolor Green " - Password er resettet på bruger"
        }
    Else
        {
        Write-host -foregroundcolor Red " - Password er ikke resettet på bruger"
        }
        
    #Verificering af Præfiks (Fratrådt_) er sat på bruger
        $prefix = Get-Aduser -Identity $bruger | select name
        $prefixEQ = "fratrådt_*"

    if ($prefix.name -match $prefixEQ)
        {
        Write-host -foregroundcolor Green " - 'Fratrådt' prefix er påsat brugers navn"
        }
    Else
        {
        Write-host -foregroundcolor Red " - 'Fratrådt' prefix er ikke påsat brugers navn"
        }
        
    #Verificering af Mail og telephone er fjernet
        $TjekTLF = Get-ADUser -Identity $bruger -Property mobile, homephone, pager, mail | Select mobile, homephone, pager, mail
    if($TjekTLF.mobile -eq $NULL -and $TjekTLF.pager -eq $NULL -and $TjekTLF.homephone -eq $NULL -and $TjekTLF.mail -eq $NULL)
        {
    Write-Host -ForegroundColor Green " - Bruger har fået fjernet Mail, Mobile, Pager og Homephone"
        }
    else
        {
        Write-Host -ForegroundColor red " - Bruger har ikke fået fjernet Mail, Mobile, Pager og Homephone"
        }
        pause


    ############################################################################### Tidsreg paste ####################################################################################


        clear

        $Dag = get-date -Format dd

        Write-host -backgroundcolor red "  Copy/Paste nedeståenden ind i ticket til tidsregistring"
        Write-Host 
        "
    REKV: Service Aftale

•	Nedlæggelse af bruger $bruger@fibia.dk
•	Tilføjet Bruger lukket $Dag-$MM-2023 - CSD-$CSD i description på brugerens AD konto
•	Verificeret at brugeren har en postkasse i Fibia - Hvis brugeren har en postkasse, følg exchange steps i guide
•	Tilføjet autosvar i postkasse
•	Konverteret postkasse til Delt Postkasse
•	Verificeret at brugeren ikke har Microsoft Teams nummer (fjernet)
•	Reset password i on-premises Active Directory
•	Deaktiver bruger i on-premises Active Directory
•	Fjernet Office 365 licenser fra brugeren i Microsoft 365 admin center
•	Flyt bruger til OU
•	Fjernet bruger fra on-premise Active Directory sikkerhedsgrupper
•	Fjernet Email fra brugeren i Active Direcotory 
•	Fjernet Telefonnummer i fanen Telephones 
•	Fjernet bruger fra Azure sikkerhedsgrupper Azure Active Directory admin center 
•	Fjernet bruger fra distributionsliste
•	Omdøb bruger med præfiks med Fratrådt_ og ændre display name på brugeren
•	Sat msExchHideFromAddressLists til TRUE i Attribute Editor I on-premises Active Directory
•	Sat Proxyaddresses til enkelt SMTP i Attribute Editor I on-premises Active Directory
•	Kontrol af MailNickname i Attribute Editor I on-premises Active Directory
•	igangsat manuel sync med AAD Connect
•	kontrolleret at brugeren er blokeret og præfiks er synligt efter manuel sync med AAD Connect
•	Sendt mail til itsupportoest@fibia vedr. lukning 
•	Vinget opgave udført i Sharepoint Link
•	Send mail til ler@fibia.dk vedr. lukning
"
        pause
}

function Hastenedlaeggelse
{
#______________________________________Local AD Del 1____________________________________#


#Indtastning af brugernavn
$bruger = read-host "Indtast brugernavn på bruger"

# Finder Displayname på bruger
$Displayname2 = Get-ADUser -Identity $bruger -Properties DisplayName
$displayname = $displayname2.DisplayName

# Generer password til bruger.
$password = [System.Web.Security.Membership]::GeneratePassword(16, 2)

# Ændre password på bruger.
Set-ADAccountPassword -Identity $bruger -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)

# Disabler bruger
Disable-ADAccount -Identity $bruger

# gemmer bruger fra address liste i AD
Set-ADUser -Identity $bruger -Add @{msExchHideFromAddressLists="TRUE"}


#________________________________________365____________________________________#


#Forbinder til Azure
Connect-AzureAD

# Revoker alle session bruger er logget ind i.
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser $bruger).ObjectId

# gemmer bruger fra address liste i Azure AD
Set-AzureADUser -ObjectId (Get-AzureADUser $bruger).ObjectId -HiddenFromAddressListsEnabled $true

#Afslutter Azure session
Disconnect-AzureAD


#______________________________________Local AD Del 2____________________________________#


start-sleep -seconds 120

# Flytter bruger til No Sync OU
Move-ADObject -Identity $bruger -TargetPath "OU=NewOU,DC=domain,DC=com"

# Updatere brugers displayname i on-prem AD med "Hastenedlagt_" prefix
Set-ADUser -Identity $bruger -DisplayName "Hastenedlagt_$($Displayname)"

Write-host "Bruger er nu blevet hastenedlagt" -ForegroundColor Green

}


    #Tjek Powershell version
function PSVersion
{
    $PSVersionTable.PSVersion

}

    #Lukker menuen ned
function LukMenu
{
    Write-Host -ForegroundColor Green 'Tak for at benytte Bruger Fibias oprettelses/nedlæggelses scriptet.'
    sleep 2
}

menu