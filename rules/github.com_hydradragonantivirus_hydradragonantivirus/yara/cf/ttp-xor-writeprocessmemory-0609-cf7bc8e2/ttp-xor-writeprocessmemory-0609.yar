rule TTP_XOR_WriteProcessMemory_0609 {
  strings:
    $key_0609 = { 51 7b [2] 63 59 [2] 65 6c [2] 4b 6c [2] 74 70 }

  condition:
    any of them
}