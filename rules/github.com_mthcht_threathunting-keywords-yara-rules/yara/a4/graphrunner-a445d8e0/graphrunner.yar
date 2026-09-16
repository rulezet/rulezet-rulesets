rule GraphRunner
{
    meta:
        description = "Detection patterns for the tool 'GraphRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphRunner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Can search all Teams messages in all channels that are readable by the current user" nocase ascii wide
                        $string2 = " Clones a security group while using an identical name and member list but can inject another user as well" nocase ascii wide
                        $string3 = "--------------------- GraphRunner Module ----------------------" nocase ascii wide
                        $string4 = /\sGraphRunner\.ps1/ nocase ascii wide
                        $string5 = " Import tokens from other tools for use in GraphRunner" nocase ascii wide
                        $string6 = "----------------------- Pillage Modules -----------------------" nocase ascii wide
                        $string7 = "----------------- Recon & Enumeration Modules -----------------" nocase ascii wide
                        $string8 = /\sSuccessful\sauthentication\.\sAccess\sand\srefresh\stokens\shave\sbeen\swritten\sto\sthe\sglobal\s\$apptokens\svariable\.\sTo\suse\sthem\swith\sother\sGraphRunner\smodules\suse\sthe\sTokens\sflag\s/ nocase ascii wide
                        $string9 = " Test different CLientID's against MSGraph to determine permissions" nocase ascii wide
                        $string10 = "# Perform the HTTP POST request to search emails" nocase ascii wide
                        $string11 = /\/GraphRunner\.git/ nocase ascii wide
                        $string12 = /\/GraphRunner\.ps1/ nocase ascii wide
                        $string13 = "/GraphRunner-main" nocase ascii wide
                        $string14 = /\/interesting\-teamsmessages\.csv/ nocase ascii wide
                        $string15 = /\/Passwords\.docx/ nocase ascii wide
                        $string16 = /\[.{0,1000}\]\sAppending\saccess\stokens\sto\saccess_tokens\.txt/ nocase ascii wide
                        $string17 = /\[.{0,1000}\]\sChecking\saccess\sto\smailboxes\sfor\seach\semail\saddress\?/ nocase ascii wide
                        $string18 = /\\\\"\-SecureString\\\\"\sOR\s\\\\"\-AsPlainText\\\\"\sOR\s\\\\"Net\.NetworkCredential\\\\"/ nocase ascii wide
                        $string19 = /\\GraphRunner\.ps1/ nocase ascii wide
                        $string20 = /\\GraphRunner\-main/ nocase ascii wide
                        $string21 = /\\interesting\-teamsmessages\.csv/ nocase ascii wide
                        $string22 = /\\Passwords\.docx/ nocase ascii wide
                        $string23 = /\]\sListing\sGraphRunner\smodules\?/ nocase ascii wide
                        $string24 = "---All Azure AD User Principal Names---" nocase ascii wide
                        $string25 = /Beau\sBullock\s\(\@dafthack\)/ nocase ascii wide
                        $string26 = "dafthack/GraphRunner" nocase ascii wide
                        $string27 = /deckard\@tyrellcorporation\.io/ nocase ascii wide
                        $string28 = "DON'T RUN THIS IN YOUR WEB ROOT AS IT WILL OUTPUT ACCESS TOKENS" nocase ascii wide
                        $string29 = /filetype\:credentials.{0,1000}\sAND\s\(\(client_id\sOR\sclientID\)\sAND\s\(tenant\)\sAND\s\(secret\)\)/ nocase ascii wide
                        $string30 = /filetype\:credentials.{0,1000}\sAND\s\(\\\\"AWS_ACCESS_KEY_ID\\\\"\sOR\s\\\\"AWS_SECRET_ACCESS_KEY\\\\"/ nocase ascii wide
                        $string31 = /filetype\:credentials.{0,1000}\sAND\s\(begin\sNEAR\(n\=1\)\s\(RSA\sOR\sOPENSSH\sOR\sDSA\sOR\sEC\sOR\sPGP\)\sNEAR\(n\=1\)\sKEY\)/ nocase ascii wide
                        $string32 = /filetype\:pem.{0,1000}AND\s\(\\\\"BEGIN\sRSA\sPRIVATE\sKEY\\\\"\sOR\s\\\\"BEGIN\sDSA\sPRIVATE\sKEY\\\\"\sOR\s\\\\"BEGIN\sEC\sPRIVATE\sKEY\\/ nocase ascii wide
                        $string33 = "Get-AzureADUsers " nocase ascii wide
                        $string34 = "Get-GraphTokens" nocase ascii wide
                        $string35 = "Get-SharePointSiteURLs" nocase ascii wide
                        $string36 = "Get-TeamsChat " nocase ascii wide
                        $string37 = /Get\-TeamsChat.{0,1000}Downloads\sfull\sTeams\schat\sconversations/ nocase ascii wide
                        $string38 = /GraphRunner.{0,1000}access_tokens\.txt/ nocase ascii wide
                        $string39 = /GraphRunner.{0,1000}chatsResponse\.json/ nocase ascii wide
                        $string40 = "GraphRunner/PHPRedirector" nocase ascii wide
                        $string41 = /GraphRunner\\PHPRedirector/ nocase ascii wide
                        $string42 = /GraphRunnerGUI\.html/ nocase ascii wide
                        $string43 = /Guest\sUser\sPolicy\:\sGuest\susers\shave\sthe\ssame\saccess\sas\smembers\s\(most\sinclusive\)/ nocase ascii wide
                        $string44 = /http\:\/\/localhost\:8000\/emailviewer\.html/ nocase ascii wide
                        $string45 = /https\:\/\/YOURREDIRECTWEBSERVER\.azurewebsites\.net/ nocase ascii wide
                        $string46 = /iamlordvoldemort\@31337schoolofhackingandwizardry\.com/ nocase ascii wide
                        $string47 = "Invoke-AutoOAuthFlow" nocase ascii wide
                        $string48 = /Invoke\-AutoTokenRefresh.{0,1000}access_token\.txt/ nocase ascii wide
                        $string49 = "Invoke-BruteClientIDAccess" nocase ascii wide
                        $string50 = "Invoke-CheckAccess" nocase ascii wide
                        $string51 = /Invoke\-DeleteGroup\s\-Tokens\s.{0,1000}\s\-groupID\s/ nocase ascii wide
                        $string52 = "Invoke-DeleteOAuthApp -Tokens " nocase ascii wide
                        $string53 = "Invoke-DeleteOAuthApp" nocase ascii wide
                        $string54 = "Invoke-DriveFileDownload" nocase ascii wide
                        $string55 = "Invoke-DriveFileDownload" nocase ascii wide
                        $string56 = "Invoke-DumpApps" nocase ascii wide
                        $string57 = "Invoke-DumpCAPS" nocase ascii wide
                        $string58 = "Invoke-ForgeUserAgent -Device " nocase ascii wide
                        $string59 = "Invoke-GraphOpenInboxFinder -Tokens" nocase ascii wide
                        $string60 = "Invoke-GraphOpenInboxFinder" nocase ascii wide
                        $string61 = "Invoke-GraphRecon" nocase ascii wide
                        $string62 = "Invoke-GraphRunner" nocase ascii wide
                        $string63 = "Invoke-HTTPServer" nocase ascii wide
                        $string64 = "Invoke-ImmersiveFileReader" nocase ascii wide
                        $string65 = "Invoke-InjectOAuthApp -AppName " nocase ascii wide
                        $string66 = "Invoke-InjectOAuthApp" nocase ascii wide
                        $string67 = "Invoke-InviteGuest" nocase ascii wide
                        $string68 = /Invoke\-RefreshAzureAppTokens\s\-ClientId\s.{0,1000}\s\-ClientSecret\s/ nocase ascii wide
                        $string69 = "Invoke-RefreshGraphTokens" nocase ascii wide
                        $string70 = "Invoke-RefreshToSharePointToken" nocase ascii wide
                        $string71 = "Invoke-SearchMailbox" nocase ascii wide
                        $string72 = "Invoke-SearchSharePointAndOneDrive" nocase ascii wide
                        $string73 = "Invoke-SearchTeams -Tokens " nocase ascii wide
                        $string74 = /Invoke\-SearchUserAttributes.{0,1000}Search\sfor\sterms\sacross\sall\suser\sattributes\sin\sa\sdirectory/ nocase ascii wide
                        $string75 = "Invoke-SecurityGroupCloner -Tokens " nocase ascii wide
                        $string76 = "Invoke-SecurityGroupCloner" nocase ascii wide
                        $string77 = /Listening\sfor\sincoming\srequests\son\shttp\:\/\/localhost\:\$port\// nocase ascii wide
                        $string78 = "List-GraphRunnerModules" nocase ascii wide
                        $string79 = /PHPRedirector.{0,1000}AutoOAuthFlow\.py/ nocase ascii wide
                        $string80 = "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" nocase ascii wide

    condition:
        any of them
}