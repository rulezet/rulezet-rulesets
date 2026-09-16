rule TTP_XOR_WriteProcessMemory_aef7 {
  strings:
    $key_aef7 = { f9 85 [2] cb a7 [2] cd 92 [2] e3 92 [2] dc 8e }

  condition:
    any of them
}