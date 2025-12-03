import pandas as pd
import numpy as np
import csv
import sys

def data_preprocessing(file_name, csv_file_name):
    #converts the conn.log.labeled file into a csv by stripping each line of all the whitespace and splitting each line by the tab marks
    with open(file_name, "r") as file:
        with open(csv_file_name, "w", newline="") as output:
            csv_writer = csv.writer(output)
            for line in file:
                stripped_line = line.strip()
                #used to indicated where the column header names are in theses specific conn.log.labeled files
                if line.startswith("#fields"):
                    line = stripped_line.split("\t")[1:]
                    csv_writer.writerow(line)
                elif not line.startswith("#"):
                    line = line.split("\t")
                    csv_writer.writerow(line)

    #creating a pandas dataframe out of the csv file
    df = pd.read_csv(csv_file_name)

    #renaming the last column to label
    df = df.rename(columns={df.columns[-1] : 'label'})

    #editing the values in the last column to only be malicious or bengin if they contain that word 
    df['label'].loc[df['label'].str.contains("malicious", case=False, na=False)] = "Malicious"
    df['label'].loc[df['label'].str.contains("benign", case=False, na=False)] = "Benign"

    #encoding each of these columns to be numerical categorical values
    df["proto"] = df["proto"].astype("category").cat.codes
    df["service"] = df["service"].astype("category").cat.codes
    df["history"] = df["history"].astype("category").cat.codes
    df["conn_state"] = df["conn_state"].astype("category").cat.codes
    
    #replacing all - values in these columns to be numpy nan values
    df['duration'] = df['duration'].replace("-", np.nan)
    df['orig_bytes'] = df['orig_bytes'].replace("-", np.nan)
    df['resp_bytes'] = df['resp_bytes'].replace("-", np.nan)

    #dropping these columns because they do not provided substantial information for our model
    df = df.drop(["local_orig", "local_resp", "ts", "uid"], axis=1)

    #filling nans with 0's where appropriate
    df["duration"] = df["duration"].fillna(0)
    df["orig_bytes"] = df["orig_bytes"].fillna(0)
    df["resp_bytes"] = df["resp_bytes"].fillna(0)

    #Changing the Ip addresses froms strings with periods to integer numbers
    df["id.orig_h"] = df["id.orig_h"].str.replace('.','')
    pd.to_numeric(df["id.orig_h"], downcast="integer")

    df["id.resp_h"] = df["id.resp_h"].str.replace('.','')
    pd.to_numeric(df["id.resp_h"], downcast="integer")

    #writing the dataframe back into a csv
    df.to_csv(csv_file_name, index=False)

if __name__ == "__main__":
    arguments = sys.argv
    #Determines if there are not enough command line arguments and exits the program
    if len(arguments) < 2:
        print("Missing file name or output csv name")
        sys.exit(1)
    file_name = arguments[1]
    csv_file_name = arguments[2]
    #Determines if the given file name is not conn.log.labeled and if so exits the program
    if("conn.log.labeled" not in file_name):
        print("incorrect data file, looking for conn.log.labeled")
        sys.exit(1)
    #Determines if the csv file name does not have the csv extenstion and exits the program
    elif(len(csv_file_name.split('.')) == 1):
        print("csv file name missing csv extension (needs .csv at the end)")
        sys.exit(1)
    #Determines if the provided exntesion is not csv and if so exits the program
    elif csv_file_name.split('.')[1] != "csv":
        print("wrong extension, need csv extension (.csv)")
        sys.exit(1)

    data_preprocessing(file_name, csv_file_name)
    #informs the user of the program working correctly
    print("Complete")