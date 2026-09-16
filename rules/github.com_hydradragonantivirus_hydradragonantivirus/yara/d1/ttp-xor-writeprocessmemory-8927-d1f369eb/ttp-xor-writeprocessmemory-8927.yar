rule TTP_XOR_WriteProcessMemory_8927 {
  strings:
    $key_8927 = { de 55 [2] ec 77 [2] ea 42 [2] c4 42 [2] fb 5e }

  condition:
    any of them
}