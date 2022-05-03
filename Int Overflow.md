# Integer Overflow

In computing, an **integer overflow** results when a device attempts to store a numeric value that is outside of the range it can represent with a given number of digits.  These overflows occur as the result of an integer operation **does not fit within the allocated memory space**. Instead of an error in the program, it usually causes the result to be unexpected.

For an easy-to-understand example of an integer overflow, look at a mechanical odometer.  The one in the included image can only count to 999,999.  After that, it **rolls back around to 0**.  The odometer is a physical device, but a similar effect can occur in computing if interger overflow bugs aren't properly mitigated.

![Integer overflow - Wikipedia](https://upload.wikimedia.org/wikipedia/commons/5/53/Odometer_rollover.jpg)

Integer overflows are the twelth most dangerous software error in the most recent [MITRE CWE Top 25](https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html) list, because of their ability to lead to [buffer overflows](https://www.acunetix.com/blog/web-security-zone/what-is-buffer-overflow/), which are currently the number 1 most dangerous software error according to that list.

In 2015, an integer overflow vulnerability was found in Boeing’s 787 Dreamliner jets that had the potential to cause pilots to lose control of the aircraft. You can read more about this vulnerability [from the FAA here](https://s3.amazonaws.com/public-inspection.federalregister.gov/2015-10066.pdf ).  An integer overflow was also behnid the 1996 Ariane 5 rocket explosion.

https://www.youtube.com/watch?v=PK_yguLapgA

## Integer Overflow Challenge

To see an integer overflow in action, check out the following C code: 

    void read_flag() {
      FILE *f = fopen("flag.txt", "r");
      if(!f) {
        fprintf(stderr, "Failed to read flag (are you running in the right directory?)\n");
        fprintf(stderr, "(Also, make sure you are not running in a debugger, which drops privileges.)\n");
        exit(1);
      }
      char flag[100];
      flag[fread(flag, 1, 99, f)] = 0;
      printf("Nice! Here's your flag... \n%s\n", flag);
    }
    
    int main( ) {
       short current = 2;
       short maximum = 9;
       short newFactor;
       int entered;
    
       printf("   Warp Drive Status\n");
       printf("-----------------------\n");
       printf("Current Warp Factor: %d\n", current);
       printf("Maximum Warp Factor: %d\n\n", maximum);
    
       printf("Set New Warp Factor: ");
       scanf("%d", &entered);
    
       newFactor = entered;
       printf("\nUpdated Warp Factor: %d\n\n", newFactor);
    
       if (entered == 10)
        printf("Sorry! The maximum warp factor is 9.\n");
       else if (newFactor > 10)
        printf("Sorry! The maximum warp factor is 9.\n");
       else if (newFactor < 10)
        printf("That's not high enough! To get the flag, the warp factor needs to bet set to 10.\n");
       else if (newFactor == 10)
        read_flag();
       else
        printf("Error!  Exiting the program...\n");
       return 0;
    }
The compiled version of this binary is located in **~/home/integer_overflow/**.  From the source code, we can see the goal is to set the program's "warp factor" to 10, but the maximum input the program will accept is 9.  ***Or is it?***

Check out the variable declarations at the beginning of the `main()` function.

       short current = 2;
       short maximum = 9;
       short newFactor;
       int entered;

**Notice anything unusual?**  See if you can find a way to circumvent the size check against the user’s input to retrieve the flag.