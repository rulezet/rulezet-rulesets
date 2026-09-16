rule TTP_XOR_WriteProcessMemory_8b1f {
  strings:
    $key_8b1f = { dc 6d [2] ee 4f [2] e8 7a [2] c6 7a [2] f9 66 }

  condition:
    any of them
}