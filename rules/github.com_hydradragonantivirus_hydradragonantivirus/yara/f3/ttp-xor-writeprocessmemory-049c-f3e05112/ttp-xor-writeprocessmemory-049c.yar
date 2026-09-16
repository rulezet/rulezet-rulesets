rule TTP_XOR_WriteProcessMemory_049c {
  strings:
    $key_049c = { 53 ee [2] 61 cc [2] 67 f9 [2] 49 f9 [2] 76 e5 }

  condition:
    any of them
}