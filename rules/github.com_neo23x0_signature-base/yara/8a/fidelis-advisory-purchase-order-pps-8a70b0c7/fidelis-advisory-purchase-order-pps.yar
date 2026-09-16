rule Fidelis_Advisory_Purchase_Order_pps {
    meta:
        description = "Detects a string found in a malicious document named Purchase_Order.pps"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://goo.gl/ZjJyti"
        date = "2015-06-09"
        id = "205c4cda-6874-5455-8eb9-b63fb09b13fd"
    strings:
        $s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii
    condition:
        all of them
}