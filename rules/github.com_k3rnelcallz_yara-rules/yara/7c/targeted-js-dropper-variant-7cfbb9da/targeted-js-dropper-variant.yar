rule Targeted_JS_Dropper_Variant {
    meta:
        description = "Detects specific JS dropper variant using ActiveX and identified obfuscation strings"
        author = "k3rnelcallz"
        reference = "malwarebazaar"
        date = "29-12-25"

    strings:
                $fn_del = "ThreeCharsDEL" ascii wide

                $fn_ww = "function WWWWWWWWW(" ascii wide

                $obfs_split = ".split('>').join('')" ascii wide

                $ax_1 = "ActiveXObject" ascii wide
        $ax_2 = ".FileExists" ascii wide

                        $var_url = /var\s+urlnameo{5,}/ ascii wide

                $var_obfs = /this\.[A-Z]{5,}\s*\+=\s*['"]/ ascii wide
        
     	        $fn_d2h = "this.d2h" ascii wide

    condition:

        $fn_del or (3 of ($fn_ww, $obfs_split, $ax_1, $ax_2, $var_url, $var_obfs, $fn_d2h))
}