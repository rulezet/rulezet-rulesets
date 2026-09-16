rule PEiD_00478_DiskDupe__c__MSD_Configuration_file_ {
  meta:
    description = "[DiskDupe (c) MSD Configuration file]"
    ep_only     = "false"

  strings:
    $a = "MSD Data Vers"

  condition:
    $a
}