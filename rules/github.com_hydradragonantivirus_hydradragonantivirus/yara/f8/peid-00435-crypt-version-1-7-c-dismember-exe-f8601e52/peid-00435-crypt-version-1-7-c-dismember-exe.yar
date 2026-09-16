rule PEiD_00435_CRYPT_Version_1_7__c__Dismember__EXE__ {
  meta:
    description = "[CRYPT Version 1.7 (c) Dismember (EXE)]"
    ep_only     = "true"

  strings:
    $a = { 0E 17 9C 58 F6 ?? ?? 74 ?? E9 }

  condition:
    $a
}