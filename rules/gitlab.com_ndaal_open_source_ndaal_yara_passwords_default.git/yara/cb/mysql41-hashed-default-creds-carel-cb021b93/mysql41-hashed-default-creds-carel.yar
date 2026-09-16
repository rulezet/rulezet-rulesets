rule mysql41_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5999B676A27C3F09595EA7E474A630190D9DFA0A"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*7F197929184D2FF4703EE39C9ACB538CF773690B"
    $a3="*3C0914F73A6E8734370D90FED73F5A0448C19D3C"
    $a4="*067FE572F26E17D78F0D63F57DFFC49841898798"
    $a5="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a6="*4971FA2AEBC3A3DF92BB304C2784CEE83CB2C315"
    $a7="*FD8BD21E333105A80A16759310D133CE1DD8A840"
    $a8="*471CD179BF428F243B07B8FECDBCE0A996987E8E"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a12="*98019C71C7E00D5A16FEA2C358E8D8D35111F31D"
    $a13="*7F571BDAAAEED0D2E6E1DE51639F4F317653AE67"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}