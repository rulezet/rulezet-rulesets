rule webshell_asp_encoded
{
	meta:
		description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/03/14"

	strings:
		$encoded1 = "VBScript.Encode" nocase wide ascii
		$encoded2 = "JScript.Encode" nocase wide ascii
		$data1 = "#@~^" wide ascii
		$sus1 = "shell" nocase wide ascii
		$sus2 = "cmd" fullword wide ascii
		$sus3 = "password" fullword wide ascii
		$sus4 = "UserPass" fullword wide ascii
	
				$tagasp_short1 = /<%[^"]/ wide ascii
        		$tagasp_short2 = "%>" wide ascii

        		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
        		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

                
                
                                                                                        		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

                $php1 = "<?php"
        $php2 = "<?="

                $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword
        
	
	condition:
		filesize < 500KB and ( 
        (
            any of ( $tagasp_long* ) or
                        any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize ) 
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize ) 
                )
            ) 
        ) and not ( 
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0 
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        ) 
		)
		and any of ( $encoded* ) and any of ( $data* ) and 
		( any of ( $sus* ) or 
		( filesize < 20KB and #data1 > 4 ) or 
		( filesize < 700 and #data1 > 0 ) )
}