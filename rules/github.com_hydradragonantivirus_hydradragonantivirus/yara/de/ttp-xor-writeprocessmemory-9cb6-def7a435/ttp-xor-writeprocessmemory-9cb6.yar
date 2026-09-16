rule TTP_XOR_WriteProcessMemory_9cb6 {
  strings:
    $key_9cb6 = { cb c4 [2] f9 e6 [2] ff d3 [2] d1 d3 [2] ee cf }

  condition:
    any of them
}