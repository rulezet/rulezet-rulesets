rule TTP_XOR_WriteProcessMemory_986b {
  strings:
    $key_986b = { cf 19 [2] fd 3b [2] fb 0e [2] d5 0e [2] ea 12 }

  condition:
    any of them
}