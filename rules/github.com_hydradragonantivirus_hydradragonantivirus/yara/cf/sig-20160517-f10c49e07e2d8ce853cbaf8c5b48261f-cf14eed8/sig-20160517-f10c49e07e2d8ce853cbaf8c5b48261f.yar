rule sig_20160517_f10c49e07e2d8ce853cbaf8c5b48261f {
  meta:
    description = "datamaliciousorder - file 20160517_f10c49e07e2d8ce853cbaf8c5b48261f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f464b6ab269491a84358159c9757f01d035570c831fe15392ad570f09205a878"

  strings:
    $s1 = "var fzur='vdawbgavgj4hrf1rbr etu4vggbb2b3wjvkd4umisskmv3dzps2zbdvwh2llrxrr3tomfcstrcngxg=ercby\\'gq1avttvdehcwa4jcnigm43ianqqlfe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}