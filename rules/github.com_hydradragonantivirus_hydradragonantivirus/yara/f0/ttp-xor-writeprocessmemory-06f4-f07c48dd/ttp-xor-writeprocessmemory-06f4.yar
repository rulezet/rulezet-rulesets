rule TTP_XOR_WriteProcessMemory_06f4 {
  strings:
    $key_06f4 = { 51 86 [2] 63 a4 [2] 65 91 [2] 4b 91 [2] 74 8d }

  condition:
    any of them
}