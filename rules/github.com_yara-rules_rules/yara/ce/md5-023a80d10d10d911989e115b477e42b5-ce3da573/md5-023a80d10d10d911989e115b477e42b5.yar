rule md5_023a80d10d10d911989e115b477e42b5 {
    strings: $ = /chr\(\d{,3}\)\.\"\"\.chr\(\d{,3}\)/
    condition: any of them
}