rule TTP_XOR_WriteProcessMemory_98da {
  strings:
    $key_98da = { cf a8 [2] fd 8a [2] fb bf [2] d5 bf [2] ea a3 }

  condition:
    any of them
}