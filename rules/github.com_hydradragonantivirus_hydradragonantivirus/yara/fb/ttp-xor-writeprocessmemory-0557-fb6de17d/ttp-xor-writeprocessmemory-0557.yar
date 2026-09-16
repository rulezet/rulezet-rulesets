rule TTP_XOR_WriteProcessMemory_0557 {
  strings:
    $key_0557 = { 52 25 [2] 60 07 [2] 66 32 [2] 48 32 [2] 77 2e }

  condition:
    any of them
}