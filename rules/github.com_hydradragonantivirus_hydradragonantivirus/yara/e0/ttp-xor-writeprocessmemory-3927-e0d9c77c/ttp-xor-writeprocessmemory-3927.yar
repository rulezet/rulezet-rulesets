rule TTP_XOR_WriteProcessMemory_3927 {
  strings:
    $key_3927 = { 6e 55 [2] 5c 77 [2] 5a 42 [2] 74 42 [2] 4b 5e }

  condition:
    any of them
}