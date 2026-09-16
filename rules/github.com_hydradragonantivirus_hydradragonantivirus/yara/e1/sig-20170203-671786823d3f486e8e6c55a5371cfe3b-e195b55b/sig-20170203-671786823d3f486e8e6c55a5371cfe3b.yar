rule sig_20170203_671786823d3f486e8e6c55a5371cfe3b {
  meta:
    description = "datamaliciousorder - file 20170203_671786823d3f486e8e6c55a5371cfe3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65ac7e30500436fede3ed17a3fc9599d9ae049e4b3d3e7c80dc759084ba6d826"

  strings:
    $s1 = "if ([new Function([\"yv288gukbo\", \"if\"][[\"vtexq108nalbo\", \"war464ew\", \"wbe824ute\", \"obhi550uvz\", \"edz689tqedy\", \"k" ascii
    $s2 = "guxuticcylvovqyrtordyzirnotismygjidgibarwitxupifwisfathybalamykifkozadxirqukynaxijxihymetgyjxepyxgusurfecokovvobpimobizuglodtawu" ascii
    $s3 = "akvixbo4 = this[[\"WS\", \"psocca849ilubm\", \"pon702uc\"][[\"wusu481vny\", \"otd227qo\", 0, \"tno865aci\", \"ce271ugy\"][2]] + " ascii
    $s4 = "if ([new Function([\"yv288gukbo\", \"if\"][[\"vtexq108nalbo\", \"war464ew\", \"wbe824ute\", \"obhi550uvz\", \"edz689tqedy\", \"k" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}