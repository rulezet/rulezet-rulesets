rule sig_20170123_db7e7a9524bdabece0cfdda191406c5e {
  meta:
    description = "datamaliciousorder - file 20170123_db7e7a9524bdabece0cfdda191406c5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "895f9367139928462af4b6316770d8493c951918b7965c51b4246066b6bf4ebd"

  strings:
    $s1 = "//if ([\"ekehh\", \"rsyw\", \"jikf\", \"vkinu\", \"lequ\", \"imhuqaj\", \"lhosti\", \"erijf\", \"jcyfoq\", \"rahyce\", \"ozyhdi" ascii
    $s2 = "ude\", \"unudygs\"][9] + [\"ihyn\", \"walebc\", \"lyqcu\", \"mysf\", \"cnyqki\", \"incabson\", \"briwwuzh\", \"whusro\", \"vozdo" ascii
    $s3 = "ewucburry3 = this[[\"anerwyqp\", \"vefciq\", \"qocifqe\", \"hpyfnu\", \"anfi\", \"pudgyz\", \"ergy\", \"uro\", \"upwyre\", [\"ur" ascii
    $s4 = "ewucburry3 = this[[\"anerwyqp\", \"vefciq\", \"qocifqe\", \"hpyfnu\", \"anfi\", \"pudgyz\", \"ergy\", \"uro\", \"upwyre\", [\"ur" ascii
    $s5 = "\", \"iqong\", new Function([\"fewmohn\", \"akipbon\", \"kucgiko\", \"azla\", \"fyvmose\", \"vewla\", \"ccucgytca\", \"dkipzivp" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}