import argparse
import csv
import numpy as np
import sys

def analyse(file_path, scheme):

    if scheme == "ds":
        list_of_algorithms = ['KeyGen', 'Sign', 'Verify']

    if scheme == "ibs":
        list_of_algorithms = ['Setup', 'KeyExtract', 'Sign']
    
    try:
        column_data = [[], [], []]

        with open(file_path, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile)
            for i, row in enumerate(reader):
                if len(row) != 3:
                    print(f"Error: Row {i+1} does not have exactly 3 columns. Skipping row.", file=sys.stderr)
                    continue
                try:
                    for col_idx in range(3):
                        column_data[col_idx].append(float(row[col_idx]))
                except ValueError:
                    print(f"Error: Non-numeric data found in row {i+1}. Skipping row.", file=sys.stderr)
                    continue

        if not any(column_data):
            print("Error: No valid numeric data found in the CSV file or file is empty.", file=sys.stderr)
            return

        for col_idx, data in enumerate(column_data):
            if not data:
                print(f"Warning: No valid numeric data for Column {col_idx + 1}. Cannot calculate statistics.", file=sys.stderr)
                continue

            np_data = np.array(data)

            average = np.mean(np_data)
            std_dev = np.std(np_data)

            print(f"--- {list_of_algorithms[col_idx]} ---")
            print(f"Average: {average:.8f}")
            print(f"Standard Deviation: {std_dev:.8f}")
            print("-" * 20)

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = "Calculate average and standard deviation for each of three columns (algorithms of a cryptographic scheme) in a CSV file."
    )
    parser.add_argument(
        "csv_file",
        type = str,
        help = "Path to the input CSV file with three columns."
    )

    parser.add_argument(
        "scheme",
        type = str,
        help = "Name of the scheme: ds (digital signature) or ibs (identity-based signature)"
    )

    args = parser.parse_args()

    analyse(args.csv_file, args.scheme)
