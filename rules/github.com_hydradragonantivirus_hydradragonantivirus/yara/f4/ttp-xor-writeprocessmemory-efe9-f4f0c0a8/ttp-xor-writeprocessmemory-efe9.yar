rule TTP_XOR_WriteProcessMemory_efe9 {
  strings:
    $key_efe9 = { b8 9b [2] 8a b9 [2] 8c 8c [2] a2 8c [2] 9d 90 }

  condition:
    any of them
}