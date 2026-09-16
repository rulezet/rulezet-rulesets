rule rule_GraphRunner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GraphRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphRunner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GraphRunner_offensive_tool_keyword = " Can search all Teams messages in all channels that are readable by the current user" nocase ascii wide
                        $string2_GraphRunner_offensive_tool_keyword = " Clones a security group while using an identical name and member list but can inject another user as well" nocase ascii wide
                        $string3_GraphRunner_offensive_tool_keyword = "--------------------- GraphRunner Module ----------------------" nocase ascii wide
                        $string4_GraphRunner_offensive_tool_keyword = /\sGraphRunner\.ps1/ nocase ascii wide
                        $string5_GraphRunner_offensive_tool_keyword = " Import tokens from other tools for use in GraphRunner" nocase ascii wide
                        $string6_GraphRunner_offensive_tool_keyword = "----------------------- Pillage Modules -----------------------" nocase ascii wide
                        $string7_GraphRunner_offensive_tool_keyword = "----------------- Recon & Enumeration Modules -----------------" nocase ascii wide
                        $string8_GraphRunner_offensive_tool_keyword = /\sSuccessful\sauthentication\.\sAccess\sand\srefresh\stokens\shave\sbeen\swritten\sto\sthe\sglobal\s\$apptokens\svariable\.\sTo\suse\sthem\swith\sother\sGraphRunner\smodules\suse\sthe\sTokens\sflag\s/ nocase ascii wide
                        $string9_GraphRunner_offensive_tool_keyword = " Test different CLientID's against MSGraph to determine permissions" nocase ascii wide
                        $string10_GraphRunner_offensive_tool_keyword = "# Perform the HTTP POST request to search emails" nocase ascii wide
                        $string11_GraphRunner_offensive_tool_keyword = /\/GraphRunner\.git/ nocase ascii wide
                        $string12_GraphRunner_offensive_tool_keyword = /\/GraphRunner\.ps1/ nocase ascii wide
                        $string13_GraphRunner_offensive_tool_keyword = "/GraphRunner-main" nocase ascii wide
                        $string14_GraphRunner_offensive_tool_keyword = /\/interesting\-teamsmessages\.csv/ nocase ascii wide
                        $string15_GraphRunner_offensive_tool_keyword = /\/Passwords\.docx/ nocase ascii wide
                        $string16_GraphRunner_offensive_tool_keyword = /\[.{0,1000}\]\sAppending\saccess\stokens\sto\saccess_tokens\.txt/ nocase ascii wide
                        $string17_GraphRunner_offensive_tool_keyword = /\[.{0,1000}\]\sChecking\saccess\sto\smailboxes\sfor\seach\semail\saddress\?/ nocase ascii wide
                        $string18_GraphRunner_offensive_tool_keyword = /\\\\"\-SecureString\\\\"\sOR\s\\\\"\-AsPlainText\\\\"\sOR\s\\\\"Net\.NetworkCredential\\\\"/ nocase ascii wide
                        $string19_GraphRunner_offensive_tool_keyword = /\\GraphRunner\.ps1/ nocase ascii wide
                        $string20_GraphRunner_offensive_tool_keyword = /\\GraphRunner\-main/ nocase ascii wide
                        $string21_GraphRunner_offensive_tool_keyword = /\\interesting\-teamsmessages\.csv/ nocase ascii wide
                        $string22_GraphRunner_offensive_tool_keyword = /\\Passwords\.docx/ nocase ascii wide
                        $string23_GraphRunner_offensive_tool_keyword = /\]\sListing\sGraphRunner\smodules\?/ nocase ascii wide
                        $string24_GraphRunner_offensive_tool_keyword = "---All Azure AD User Principal Names---" nocase ascii wide
                        $string25_GraphRunner_offensive_tool_keyword = /Beau\sBullock\s\(\@dafthack\)/ nocase ascii wide
                        $string26_GraphRunner_offensive_tool_keyword = "dafthack/GraphRunner" nocase ascii wide
                        $string27_GraphRunner_offensive_tool_keyword = /deckard\@tyrellcorporation\.io/ nocase ascii wide
                        $string28_GraphRunner_offensive_tool_keyword = "DON'T RUN THIS IN YOUR WEB ROOT AS IT WILL OUTPUT ACCESS TOKENS" nocase ascii wide
                        $string29_GraphRunner_offensive_tool_keyword = /filetype\:credentials.{0,1000}\sAND\s\(\(client_id\sOR\sclientID\)\sAND\s\(tenant\)\sAND\s\(secret\)\)/ nocase ascii wide
                        $string30_GraphRunner_offensive_tool_keyword = /filetype\:credentials.{0,1000}\sAND\s\(\\\\"AWS_ACCESS_KEY_ID\\\\"\sOR\s\\\\"AWS_SECRET_ACCESS_KEY\\\\"/ nocase ascii wide
                        $string31_GraphRunner_offensive_tool_keyword = /filetype\:credentials.{0,1000}\sAND\s\(begin\sNEAR\(n\=1\)\s\(RSA\sOR\sOPENSSH\sOR\sDSA\sOR\sEC\sOR\sPGP\)\sNEAR\(n\=1\)\sKEY\)/ nocase ascii wide
                        $string32_GraphRunner_offensive_tool_keyword = /filetype\:pem.{0,1000}AND\s\(\\\\"BEGIN\sRSA\sPRIVATE\sKEY\\\\"\sOR\s\\\\"BEGIN\sDSA\sPRIVATE\sKEY\\\\"\sOR\s\\\\"BEGIN\sEC\sPRIVATE\sKEY\\/ nocase ascii wide
                        $string33_GraphRunner_offensive_tool_keyword = "Get-AzureADUsers " nocase ascii wide
                        $string34_GraphRunner_offensive_tool_keyword = "Get-GraphTokens" nocase ascii wide
                        $string35_GraphRunner_offensive_tool_keyword = "Get-SharePointSiteURLs" nocase ascii wide
                        $string36_GraphRunner_offensive_tool_keyword = "Get-TeamsChat " nocase ascii wide
                        $string37_GraphRunner_offensive_tool_keyword = /Get\-TeamsChat.{0,1000}Downloads\sfull\sTeams\schat\sconversations/ nocase ascii wide
                        $string38_GraphRunner_offensive_tool_keyword = /GraphRunner.{0,1000}access_tokens\.txt/ nocase ascii wide
                        $string39_GraphRunner_offensive_tool_keyword = /GraphRunner.{0,1000}chatsResponse\.json/ nocase ascii wide
                        $string40_GraphRunner_offensive_tool_keyword = "GraphRunner/PHPRedirector" nocase ascii wide
                        $string41_GraphRunner_offensive_tool_keyword = /GraphRunner\\PHPRedirector/ nocase ascii wide
                        $string42_GraphRunner_offensive_tool_keyword = /GraphRunnerGUI\.html/ nocase ascii wide
                        $string43_GraphRunner_offensive_tool_keyword = /Guest\sUser\sPolicy\:\sGuest\susers\shave\sthe\ssame\saccess\sas\smembers\s\(most\sinclusive\)/ nocase ascii wide
                        $string44_GraphRunner_offensive_tool_keyword = /http\:\/\/localhost\:8000\/emailviewer\.html/ nocase ascii wide
                        $string45_GraphRunner_offensive_tool_keyword = /https\:\/\/YOURREDIRECTWEBSERVER\.azurewebsites\.net/ nocase ascii wide
                        $string46_GraphRunner_offensive_tool_keyword = /iamlordvoldemort\@31337schoolofhackingandwizardry\.com/ nocase ascii wide
                        $string47_GraphRunner_offensive_tool_keyword = "Invoke-AutoOAuthFlow" nocase ascii wide
                        $string48_GraphRunner_offensive_tool_keyword = /Invoke\-AutoTokenRefresh.{0,1000}access_token\.txt/ nocase ascii wide
                        $string49_GraphRunner_offensive_tool_keyword = "Invoke-BruteClientIDAccess" nocase ascii wide
                        $string50_GraphRunner_offensive_tool_keyword = "Invoke-CheckAccess" nocase ascii wide
                        $string51_GraphRunner_offensive_tool_keyword = /Invoke\-DeleteGroup\s\-Tokens\s.{0,1000}\s\-groupID\s/ nocase ascii wide
                        $string52_GraphRunner_offensive_tool_keyword = "Invoke-DeleteOAuthApp -Tokens " nocase ascii wide
                        $string53_GraphRunner_offensive_tool_keyword = "Invoke-DeleteOAuthApp" nocase ascii wide
                        $string54_GraphRunner_offensive_tool_keyword = "Invoke-DriveFileDownload" nocase ascii wide
                        $string55_GraphRunner_offensive_tool_keyword = "Invoke-DriveFileDownload" nocase ascii wide
                        $string56_GraphRunner_offensive_tool_keyword = "Invoke-DumpApps" nocase ascii wide
                        $string57_GraphRunner_offensive_tool_keyword = "Invoke-DumpCAPS" nocase ascii wide
                        $string58_GraphRunner_offensive_tool_keyword = "Invoke-ForgeUserAgent -Device " nocase ascii wide
                        $string59_GraphRunner_offensive_tool_keyword = "Invoke-GraphOpenInboxFinder -Tokens" nocase ascii wide
                        $string60_GraphRunner_offensive_tool_keyword = "Invoke-GraphOpenInboxFinder" nocase ascii wide
                        $string61_GraphRunner_offensive_tool_keyword = "Invoke-GraphRecon" nocase ascii wide
                        $string62_GraphRunner_offensive_tool_keyword = "Invoke-GraphRunner" nocase ascii wide
                        $string63_GraphRunner_offensive_tool_keyword = "Invoke-HTTPServer" nocase ascii wide
                        $string64_GraphRunner_offensive_tool_keyword = "Invoke-ImmersiveFileReader" nocase ascii wide
                        $string65_GraphRunner_offensive_tool_keyword = "Invoke-InjectOAuthApp -AppName " nocase ascii wide
                        $string66_GraphRunner_offensive_tool_keyword = "Invoke-InjectOAuthApp" nocase ascii wide
                        $string67_GraphRunner_offensive_tool_keyword = "Invoke-InviteGuest" nocase ascii wide
                        $string68_GraphRunner_offensive_tool_keyword = /Invoke\-RefreshAzureAppTokens\s\-ClientId\s.{0,1000}\s\-ClientSecret\s/ nocase ascii wide
                        $string69_GraphRunner_offensive_tool_keyword = "Invoke-RefreshGraphTokens" nocase ascii wide
                        $string70_GraphRunner_offensive_tool_keyword = "Invoke-RefreshToSharePointToken" nocase ascii wide
                        $string71_GraphRunner_offensive_tool_keyword = "Invoke-SearchMailbox" nocase ascii wide
                        $string72_GraphRunner_offensive_tool_keyword = "Invoke-SearchSharePointAndOneDrive" nocase ascii wide
                        $string73_GraphRunner_offensive_tool_keyword = "Invoke-SearchTeams -Tokens " nocase ascii wide
                        $string74_GraphRunner_offensive_tool_keyword = /Invoke\-SearchUserAttributes.{0,1000}Search\sfor\sterms\sacross\sall\suser\sattributes\sin\sa\sdirectory/ nocase ascii wide
                        $string75_GraphRunner_offensive_tool_keyword = "Invoke-SecurityGroupCloner -Tokens " nocase ascii wide
                        $string76_GraphRunner_offensive_tool_keyword = "Invoke-SecurityGroupCloner" nocase ascii wide
                        $string77_GraphRunner_offensive_tool_keyword = /Listening\sfor\sincoming\srequests\son\shttp\:\/\/localhost\:\$port\// nocase ascii wide
                        $string78_GraphRunner_offensive_tool_keyword = "List-GraphRunnerModules" nocase ascii wide
                        $string79_GraphRunner_offensive_tool_keyword = /PHPRedirector.{0,1000}AutoOAuthFlow\.py/ nocase ascii wide
                        $string80_GraphRunner_offensive_tool_keyword = "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" nocase ascii wide

    condition:
        any of them
}