import pandas as pd
import numpy as np
import csv
import sys

def data_preprocessing(file_name, csv_file_name):
    with open(file_name, "r") as file:
        with open(csv_file_name, "w", newline="") as output:
            csv_writer = csv.writer(output)
            for line in file:
                stripped_line = line.strip()
                if line.startswith("#fields"):
                    line = line.split("\t")[1:]
                    csv_writer.writerow(line)
                elif not line.startswith("#"):
                    line = line.split("\t")
                    csv_writer.writerow(line)

    df = pd.read_csv(csv_file_name)

    df = df.rename(columns={df.columns[-1] : 'label'})

    df['label'].loc[df['label'].str.contains("malicious", case=False, na=False)] = "Malicious"
    df['label'].loc[df['label'].str.contains("benign", case=False, na=False)] = "Benign"


    df["proto"] = df["proto"].astype("category").cat.codes
    df["service"] = df["service"].astype("category").cat.codes
    df["history"] = df["history"].astype("category").cat.codes
    
    
    df['duration'] = df['duration'].replace("-", np.nan)
    df['orig_bytes'] = df['orig_bytes'].replace("-", np.nan)
    df['resp_bytes'] = df['resp_bytes'].replace("-", np.nan)


    df = df.drop(["local_orig", "local_resp", "ts", "uid"], axis=1)

    df["duration"] = df["duration"].fillna(0)
    df["orig_bytes"] = df["orig_bytes"].fillna(0)
    df["resp_bytes"] = df["resp_bytes"].fillna(0)

    df["id.orig_h"] = df["id.orig_h"].str.replace('.','')
    pd.to_numeric(df["id.orig_h"], downcast="integer")

    df["id.resp_h"] = df["id.resp_h"].str.replace('.','')
    pd.to_numeric(df["id.resp_h"], downcast="integer")

    df.to_csv(csv_file_name, index=False)

if __name__ == "__main__":
    arguments = sys.argv
    if len(arguments) < 2:
        print("Missing file name or output csv name")
        sys.exit(1)
    file_name = arguments[1]
    csv_file_name = arguments[2]
    if(file_name != "conn.log.labeled"):
        print("incorrect data file, looking for conn.log.labeled")
        sys.exit(1)
    elif(len(csv_file_name.split('.')) == 1):
        print("csv file name missing csv extension (needs .csv at the end)")
        sys.exit(1)
    elif csv_file_name.split('.')[1] != "csv":
        print("wrong extension, need csv extension (.csv)")
        sys.exit(1)

    data_preprocessing(file_name, csv_file_name)

    print("Complete")