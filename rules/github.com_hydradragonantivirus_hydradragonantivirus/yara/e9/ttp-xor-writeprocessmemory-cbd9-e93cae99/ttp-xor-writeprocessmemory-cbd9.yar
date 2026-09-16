rule TTP_XOR_WriteProcessMemory_cbd9 {
  strings:
    $key_cbd9 = { 9c ab [2] ae 89 [2] a8 bc [2] 86 bc [2] b9 a0 }

  condition:
    any of them
}