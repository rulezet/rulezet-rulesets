rule TTP_XOR_WriteProcessMemory_ead9 {
  strings:
    $key_ead9 = { bd ab [2] 8f 89 [2] 89 bc [2] a7 bc [2] 98 a0 }

  condition:
    any of them
}