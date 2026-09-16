rule reGeorg_Variant_Web_shell {
    meta:
        description = "Matches the reGeorg variant web shell used by the actors."
        date = "2021-07-01"
        author = "National Security Agency"
        source = "https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF"
        
    strings:
        $pageLanguage = "<%@ Page Language=\"C#\""
        $obfuscationFunction = "StrTr"
        $target = "target_str"
        $IPcomms = "System.Net.IPEndPoint"
        $addHeader = "Response.AddHeader"
        $socket = "Socket"
        
    condition:
        5 of them
}