rule PEiD_01161_Morphine_3_3____Silent_Software___Silent_Shield__c_2005__h__ {
  meta:
    description = "[Morphine 3.3 -> Silent Software & Silent Shield (c)2005 (h)]"
    ep_only     = "false"

  strings:
    $a = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 }

  condition:
    $a
}