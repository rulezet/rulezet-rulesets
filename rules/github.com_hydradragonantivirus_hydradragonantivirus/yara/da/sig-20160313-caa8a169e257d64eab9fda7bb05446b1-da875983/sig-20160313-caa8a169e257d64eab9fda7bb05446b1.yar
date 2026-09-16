rule sig_20160313_caa8a169e257d64eab9fda7bb05446b1 {
  meta:
    description = "datamaliciousorder - file 20160313_caa8a169e257d64eab9fda7bb05446b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef68eb0632b51588fa58bf0c2a4d8137e60a5c0c7ca9912c01513ac15fb0d163"

  strings:
    $s1  = "cssNumber[\"op\" + access](\"GE\" + combinator, \"http\" + rcombinators + \"hellog\" + _jQuery + \"f.com/\" + ajaxSettings, !(((" ascii
    $s2  = "cssNumber[\"op\" + access](\"GE\" + combinator, \"http\" + rcombinators + \"hellog\" + _jQuery + \"f.com/\" + ajaxSettings, !(((" ascii
    $s3  = "removeChild[input + \"u\" + getAttributeNode](ready, ((240, start) & (1 | start)), ((1225 / list) - (10 * id + 5)));" fullword ascii
    $s4  = "ready = step[\"Expand\" + progress + \"iro\" + nextSibling + \"tStr\" + rdashAlpha](\"%TE\" + originalOptions) + \"sou\" + trans" ascii
    $s5  = "ready = step[\"Expand\" + progress + \"iro\" + nextSibling + \"tStr\" + rdashAlpha](\"%TE\" + originalOptions) + \"sou\" + trans" ascii
    $s6  = "ajaxSettings = \"70.exe\", progress = \"Env\", pixelPosition = \"Creat\", unwrap = 11954;" fullword ascii
    $s7  = "checked[\"saveTo\" + propFix + \"e\"](ready, (1 * (showHide * 2)));" fullword ascii
    $s8  = "step = trim[\"Creat\" + selector + \"ct\"](fns + \"t.She\" + buildParams);" fullword ascii
    $s9  = "x\" + overflow + \"sc\" + original;" fullword ascii
    $s10 = "cssNumber[\"s\" + access + \"d\"]();" fullword ascii
    $s11 = "trim = this[\"WScr\" + addBack];" fullword ascii
    $s12 = "cssNumber = this[\"WScri\" + properties][\"Cre\" + marginLeft + \"bje\" + adjustCSS](\"MSXML\" + firing + \"MLH\" + fnOver);" fullword ascii
    $s13 = "checked = this[fns + \"t\"][pixelPosition + \"eObje\" + adjustCSS](\"ADODB.\" + arg + \"am\");" fullword ascii
    $s14 = "checked[matchers + \"p\" + access]();" fullword ascii
    $s15 = "transport = \"rceIn\";" fullword ascii
    $s16 = "var combinator = \"T\";" fullword ascii
    $s17 = "sports() {}, \"ings\");" fullword ascii
    $s18 = "buildParams = \"ll\", rtagName = \"wr\", marginLeft = \"ateO\", fnOver = \"TTP\", id = 2, rdashAlpha = (function inspectPrefilte" ascii
    $s19 = "function iterator() {" fullword ascii
    $s20 = "function optionSet() {" fullword ascii

  condition:
    uint16(0) == 0x6a5f and
    8 of them
}