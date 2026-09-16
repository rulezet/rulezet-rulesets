rule Mimikatz_Samples_2014b_1 {
  meta:
    description = "Mimikatz pwassword dumper samples from the second half of 2014"
    author      = "Florian Roth with the help of YarGen Rule Generator"
    reference   = "not set"
    date        = "2014/12/23"
    score       = 80
    hash        = "ef5bd09b2e5836b58a8b27c1fb3650621aaf6488"

  strings:
    $s1  = "Raw command (not implemented yet) : %s" fullword wide
    $s3  = " ! ZwSetInformationProcess 0x%08x for %u/%-14S" fullword wide
    $s6  = "PsSetCreateProcessNotifyRoutineEx" fullword wide
    $s10 = "\\Device\\mimidrv" fullword wide
    $s16 = "\\DosDevices\\mimidrv" fullword wide
    $s17 = "All privileges for the access token from %u/%-14S" fullword wide
    $s20 = "in (0x%p - %u) ; out (0x%p - %u)" fullword wide

  condition:
    all of them
}