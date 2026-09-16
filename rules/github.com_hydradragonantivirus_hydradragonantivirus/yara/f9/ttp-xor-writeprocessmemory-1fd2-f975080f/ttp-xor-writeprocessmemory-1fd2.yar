rule TTP_XOR_WriteProcessMemory_1fd2 {
  strings:
    $key_1fd2 = { 48 a0 [2] 7a 82 [2] 7c b7 [2] 52 b7 [2] 6d ab }

  condition:
    any of them
}