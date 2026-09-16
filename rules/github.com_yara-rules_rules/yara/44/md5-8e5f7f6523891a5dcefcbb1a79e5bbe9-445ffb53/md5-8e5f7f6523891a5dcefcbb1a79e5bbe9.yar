rule md5_8e5f7f6523891a5dcefcbb1a79e5bbe9 {
    strings: $ = "if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])) {echo '<b>up!!!</b><br><br>';}}"
    condition: any of them
}