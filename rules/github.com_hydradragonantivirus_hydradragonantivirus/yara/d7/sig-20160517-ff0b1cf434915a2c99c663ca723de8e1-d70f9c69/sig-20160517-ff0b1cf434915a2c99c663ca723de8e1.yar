rule sig_20160517_ff0b1cf434915a2c99c663ca723de8e1 {
  meta:
    description = "datamaliciousorder - file 20160517_ff0b1cf434915a2c99c663ca723de8e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb9fe06538a61f296124c2165d534a43d328381f3832f75d42f2cb77ee8a20d9"

  strings:
    $s1 = "var vsp2='vx4iqhaxee1urakrji do3a3qtykblaa3oxjoyhni2mefgdfqfauvo3iwce1kmiytofemr3j=w3usl\\'dqucytsh4ydcda4yjnmdv32iamncoffhrv4ut" ascii
    $s2 = " WScript.lister=5;   lbjne3rpvw=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      bge3gsmh=999" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}