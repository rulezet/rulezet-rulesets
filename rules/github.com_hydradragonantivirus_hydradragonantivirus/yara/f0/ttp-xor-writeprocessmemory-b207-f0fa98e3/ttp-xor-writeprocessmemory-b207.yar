rule TTP_XOR_WriteProcessMemory_b207 {
  strings:
    $key_b207 = { e5 75 [2] d7 57 [2] d1 62 [2] ff 62 [2] c0 7e }

  condition:
    any of them
}