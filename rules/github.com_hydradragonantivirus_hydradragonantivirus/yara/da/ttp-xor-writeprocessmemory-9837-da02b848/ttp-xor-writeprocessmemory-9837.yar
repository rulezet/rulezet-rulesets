rule TTP_XOR_WriteProcessMemory_9837 {
  strings:
    $key_9837 = { cf 45 [2] fd 67 [2] fb 52 [2] d5 52 [2] ea 4e }

  condition:
    any of them
}