rule SUSP_LNK_Has_Wiped_FileSize {
  meta:
    author      = "Greg Lesnewich, inspired by Jeremy Hedges"
    description = "track LNK files that wipe the filesize information from the link header"
    date        = "2024-02-01"
    version     = "1.0"
    DaysOfYara  = "33/100"

  condition:
    uint32be(0x0) == 0x4c000000 and
    uint32(0x34) == 0x0  }