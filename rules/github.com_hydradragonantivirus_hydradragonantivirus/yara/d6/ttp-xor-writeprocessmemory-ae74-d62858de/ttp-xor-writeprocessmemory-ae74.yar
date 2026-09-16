rule TTP_XOR_WriteProcessMemory_ae74 {
  strings:
    $key_ae74 = { f9 06 [2] cb 24 [2] cd 11 [2] e3 11 [2] dc 0d }

  condition:
    any of them
}