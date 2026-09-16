rule hidden_file_upload_in_503 {
    strings: $ = /error_reporting\(0\);\$f=\$_FILES\[\w+\];copy\(\$f\[tmp_name\],\$f\[name\]\);error_reporting\(E_ALL\);/
    condition: any of them
}