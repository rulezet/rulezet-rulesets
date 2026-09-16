rule TTP_XOR_WriteProcessMemory_cce4 {
  strings:
    $key_cce4 = { 9b 96 [2] a9 b4 [2] af 81 [2] 81 81 [2] be 9d }

  condition:
    any of them
}