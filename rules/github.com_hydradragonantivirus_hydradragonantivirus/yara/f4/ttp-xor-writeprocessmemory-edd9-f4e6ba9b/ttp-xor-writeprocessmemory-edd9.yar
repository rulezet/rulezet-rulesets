rule TTP_XOR_WriteProcessMemory_edd9 {
  strings:
    $key_edd9 = { ba ab [2] 88 89 [2] 8e bc [2] a0 bc [2] 9f a0 }

  condition:
    any of them
}