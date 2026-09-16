rule smsfraud1 : android
{
    meta:
        author = "Antonio Sánchez https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        description = "This rule detects a kind of SMSFraud trojan"
        sample = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
        sample2 = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"

    strings:
        $a = "E!QQAZXS"
        $b = "__exidx_end"
        $c = "res/layout/notify_apkinstall.xmlPK"

    condition:
    all of them
        
}