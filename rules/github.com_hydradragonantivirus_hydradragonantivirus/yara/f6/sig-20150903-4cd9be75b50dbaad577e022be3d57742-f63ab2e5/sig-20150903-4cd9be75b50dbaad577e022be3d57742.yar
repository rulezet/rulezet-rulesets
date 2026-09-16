rule sig_20150903_4cd9be75b50dbaad577e022be3d57742 {
  meta:
    description = "datamaliciousorder - file 20150903_4cd9be75b50dbaad577e022be3d57742.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14c72509627f80851c199d30923168d45fc37228b23b0f637a4092136bbc1086"

  strings:
    $s1  = " }; function nqk27ni() { return 'b.com'; }; function nqk110ni() { return ' = f'; }; function nqk95ni() { return 'tiveX'; }; func" ascii
    $s2  = "var stroke=\"5557505E09051607240C160A0111160B14014A070B09\";function nqk52ni() { return '.S'; }; function nqk118ni() { return 'S" ascii
    $s3  = " return 'ry '; }; function nqk120ni() { return ' && '; }; function nqk151ni() { return 'nse'; }; function nqk9ni() { return 'at'" ascii
    $s4  = "{ return 'rand'; }; function nqk197ni() { return 'T\",\"h'; }; function nqk195ni() { return '.ope'; }; function nqk158ni() { ret" ascii
    $s5  = " }; function nqk88ni() { return 'n = '; }; function nqk59ni() { return '.Exp'; }; function nqk229ni() { return '(515'; }; functi" ascii
    $s6  = "'; }; function nqk14ni() { return 'a.it'; }; function nqk122ni() { return '.sta'; }; function nqk99ni() { return 'ML2'; }; funct" ascii
    $s7  = ") { return '.sen'; }; function nqk142ni() { return 'ype'; }; function nqk43ni() { return '{ v'; }; function nqk29ni() { return '" ascii
    $s8  = "}; function nqk46ni() { return 'ew '; }; function nqk208ni() { return '\"&id='; }; function nqk227ni() { return ' }; }'; }; func" ascii
    $s9  = "i() { return 'rit'; }; function nqk130ni() { return 'ew Ac'; }; function nqk19ni() { return 'me.c'; }; function nqk164ni() { ret" ascii
    $s10 = "}; function nqk213ni() { return 'lse'; }; function nqk179ni() { return ',1,0'; }; function nqk56ni() { return ' fn '; }; functio" ascii
    $s11 = "turn 'a.w'; }; function nqk190ni() { return '); }'; }; function nqk170ni() { return 'To'; }; function nqk102ni() { return 'TP\")" ascii
    $s12 = "'h;'; }; function nqk68ni() { return ')+'; }; function nqk112ni() { return 'ti'; }; function nqk169ni() { return 've'; }; functi" ascii
    $s13 = "6ni() { return 'd(); '; }; function nqk211ni() { return ', '; }; function nqk131ni() { return 'tiveX'; }; function nqk20ni() { r" ascii
    $s14 = "urn 'ti'; }; function nqk133ni() { return 'ect'; }; function nqk77ni() { return 'un'; }; function nqk101ni() { return 'MLHT'; };" ascii
    $s15 = "e+'ni'](); }; this[nqk0ni()](q); " fullword ascii
    $s16 = "; }; function nqk154ni() { return ' ('; }; function nqk15ni() { return ' cros'; }; function nqk125ni() { return '200)'; }; funct" ascii
    $s17 = " { return 'l('; }; function nqk73ni() { return 'ode'; }; function nqk57ni() { return '= '; }; function nqk98ni() { return 'MSX';" ascii
    $s18 = "unction nqk162ni() { return ' xa.'; }; function nqk186ni() { return '}; x'; }; function nqk16ni() { return 'sfitr'; }; function " ascii
    $s19 = "}; function nqk137ni() { return 'm\"); '; }; function nqk23ni() { return 'onwre'; }; function nqk192ni() { return ' t'; }; funct" ascii
    $s20 = "6ni() { return 'gclu'; }; function nqk49ni() { return 'ject('; }; function nqk203ni() { return 'ument'; }; function nqk193ni() {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}