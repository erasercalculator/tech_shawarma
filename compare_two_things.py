#!/usr/bin/python
#Script made by Rohan Bhargava for comparing two files.
#Bad file is the file to be compared to the exemplar - good file
#The lines that differ from the good file are printed.
#This script usually works best if the bad file is larger than the good file.

if __name__ == "__main__":
    bad_file = input("Enter in the absolute path to the bad file:")
    good_file = input("Enter in the absolute path to the good file:")

    print()
    print("#"*50)
    print()

    try:
        for i  in open(bad_file, "r").readlines():
          match = False
          for j in open(good_file, "r").readlines():
              if i == j:
                  match = True
          if match == False:
              print(i)
    except FileNotFoundError:
        print("ERR: Incorrect file paths!")
    except Exception as e:
        print(f"Ran into unknown {e}")
