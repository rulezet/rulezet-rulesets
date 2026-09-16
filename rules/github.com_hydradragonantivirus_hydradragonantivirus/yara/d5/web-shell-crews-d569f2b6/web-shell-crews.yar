rule web_shell_crews {
  meta:
    author    = "@patrickrolsen"
    maltype   = "Web Shell Crews"
    version   = "0.4"
    reference = "http://www.exploit-db.com/exploits/24905/"
    date      = "12/29/2013"

  strings:
    $mz       = "MZ"      $string1  = "v0pCr3w"
    $string2  = "BENJOLSHELL"
    $string3  = "EgY_SpIdEr"
    $string4  = "<title>HcJ"
    $string5  = "0wn3d"
    $string6  = "OnLy FoR QbH"
    $string7  = "wSiLm"
    $string8  = "b374k r3c0d3d"
    $string9  = "x'1n73ct|d"
    $string10 = "## CREATED BY KATE ##"
    $string11 = "Ikram Ali"
    $string12 = "FeeLCoMz"
    $string13 = "s3n4t00r"
    $string14 = "FaTaLisTiCz_Fx"
    $string15 = "feelscanz.pl"
    $string16 = "##[ KONFIGURASI"
    $string17 = "Created by Kiss_Me"
    $string18 = "Casper_Cell"
    $string19 = "# [ CREWET ] #"
    $string20 = "BY MACKER"
    $string21 = "FraNGky"
    $string22 = "1dt.w0lf"
    $string23 = "Modification By iFX" nocase

  condition:
    not $mz at 0 and any of ($string*)
}