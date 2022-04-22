# ---------ॐ----------


# Original: March 18, 2021
# Update: Nov 25, 2021
# Created by: Aditya Mathur

# To find  "Who is listening on  a port ?"
# sudo lsof -nP -iTCP: port number | grep LISTEN

# March 18, 2021: Objects of this class are used to create sockets for
# receiving plant state from the twin and publishing detector objects.
# March 23, 2021: Added setDetObj() for a detector to
# pass a detector object to the DetObj object. TThe object passed
# is published for SCADA.
# June 30, 2021: Added PlantProtect
# Aug 18, 2022: Updated socket close method

# Nov 8, 2021: Added code to receive ports from SWaT_Twin.
#   The state dict received contains a key named "DetectorInfo" which
#   is a dictionary. There is a key for each detector attached to the twin.
#   The value of the key is the port number.
#   For example, {"DetectorInfo": {"AICrit": 12380, "DAD": 12382}}
#   New detectors added in real time are added to this dictionary.
# Nov 24, 2021: Added "Active" tag to anomaly object. THis is set to
#   True if detector is to publish anomaly object, False otherwise.
#   A detector activation button in the EWS interface can be used
#   to toggle this tag.
# Nov 25, 2021: Default detectors are assumed to have the same IP as the SWaT_Twin.
#   Added remoteDetectorIP. This is used to set up socket
#   at which a remote detector (newly added) will publish the anomaly object.
import csv
import time

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
import zmq
import warnings

warnings.filterwarnings('ignore')

from numpy import array


def split_sequences(sequences, n_steps):
    X, y = list(), list()
    for i in range(len(sequences)):
        # find the end of this pattern
        end_ix = i + n_steps
        # check if we are beyond the dataset
        if end_ix > len(sequences):
            break
        # gather input and output parts of the pattern
        seq_x, seq_y = sequences[i:end_ix, :-1], sequences[end_ix - 1, -1]
        X.append(seq_x)
        y.append(seq_y)
    return array(X), array(y)


def consumerIP(context, ipAddressAndPort, topic):
    socket = context.socket(zmq.SUB)  # Receive control info from GUI.
    formattedipAddressAndPort = f'tcp://{ipAddressAndPort}'
    socket.connect(formattedipAddressAndPort)
    socket.setsockopt_string(zmq.SUBSCRIBE, topic)
    return socket


def getStateof(requestingDevice, getFromDevice, socket):
    try:
        state = socket.recv()
        # dd.updateCommList((requestingDevice, fromDevice))
    except:
        socket.send_string(requestingDevice.retainCommand)
        # dd.updateCommList((requestingDevice, fromDevice))
        state = socket.recv()
        # dd.updateCommList((fromDevice, requestingDevice))
        # print("Error in getState(): ", fromDevice, requestingDevice)
    return state


def recv(requestingDevice, recvFromDevice, socket):
    return getStateof(requestingDevice, recvFromDevice, socket)


# This class is used by anomaly detectors to create DETZMQ objects.
# Each object is responsible for setting up sockets for all communications
# between the twin and the detector.

class DetZMQ:
    # Terminology:
    # State: Refers to the composite state of the plant
    # commState: String denoting successful completion of individual
    # detector communication tasks.
    # Init parameters:
    # detObj:  Dictionary with keys ID, Anomaly, and Key to be used.
    #   This is used to publish commands to a remote device.
    #   If multiple remote commands are to be published
    #   then this parameter can be converted to a list of dictionaries.

    # receiveFromTwin:  
    #   This is used to receive commands from a remote PLC.
    #   If multiple remote commands are to be published
    #   then this parameter can be converted to a list of dictionaries.

    def __init__(self, detector=None, anomalyObj=None, remoteDetectorIP=None):
        self.myClassName = "Student1_Detector"
        self.myDetName = detector
        self.commState = ""
        self.remoteDetectorIP = '192.168.2.200'  # Only for non-default detectors.

        self.SCADAPort = "5876"  # Receive state at this port (also SCADA port)
        # self.publishDetObjPort=ip.detectorPorts[detector] # Publish detObj at this port
        if (anomalyObj == None):
            self.anomalyObj = {"ID": detector,
                               "Anomaly": False,
                               "Invariants": [],
                               "Attack": [],
                               "Action": [],
                               "Operator": [],
                               "Active": False  # True for detector to publish anomaly obj
                               }  # Initial detector object to be published, can be null
        else:
            self.anomalyObj = anomalyObj
        self.commUpdate = True
        self.startPublishing = False  # Set to True when port to publish is recd.
        self.publishSocketSetup = False

        # self.setup()   # Set up to be done by the user of this class.
        return  # init()

    # Set up sockets for subcribing to and publishing states.
    def setup(self):
        remoteHMITopic = "Extract"
        separator = "!"
        self.context = zmq.Context()
        self.topicPublishRemoteHMI = remoteHMITopic + separator  # Topic used by SACDA during publishing
        self.topicFilterDetState = ""
        self.setupReceiveFromSCADASocket()  # for receiving plant state from SCADA (subscribe)
        return  # setup()

    def setupReceiveFromSCADASocket(self):
        portRemoteHMI = self.SCADAPort
        self.socketReceivePlantState = consumerIP(self.context,
                                                  f'{self.remoteDetectorIP}:{portRemoteHMI}',  # 5876
                                                  self.topicPublishRemoteHMI)

    # Get state from plant. "detectorInfo" contains the name
    # of a new detector that may have been added by the twin user.
    def getState(self):
        self.getPlantStateFromSCADA()
        detectorInfo = self.plantState["DetectorInfo"]
        # Set anomaly publish port if one is available.
        if (self.myDetName in detectorInfo):
            portToPublish = detectorInfo[self.myDetName]
            if (not self.publishSocketSetup):
                self.setupPublishDetObjSocket(portToPublish)  # Socket to publish detObj
                self.startPublishing = True
                self.publishSocketSetup = True
        return self.plantState  # getState()

    def getPlantStateFromSCADA(self):
        # Get state from SCADA
        st = recv(self.myDetName, "SCADA", self.socketReceivePlantState)
        self.plantState = st.decode("UTF-8").split('!')[1]  # Remove topic and
        self.plantState = eval(self.plantState.replace(" ", ""))  # any space in the command.
        # self.commState=ut.updateCommState(self.commState,"D: DET"+str(s)) # Update communication status (R: received)
        return

    def close(self):
        self.socketReceivePlantState.setsockopt(zmq.LINGER, 0)
        self.socketReceivePlantState.close()
        self.context.destroy()
        self.debug("All sockets closed before termination.")
        self.debug("-------------------------------------.")
        return

    def debug(self, *args):
        print(self.myClassName + ": " + self.myDetName, *args)
        return


def main():
    detector = DetZMQ()
    detector.setup()

    x_scaler = joblib.load('x_scaler.save')
    y_scaler = joblib.load('y_scaler.save')

    model = tf.keras.models.load_model('lit301.h5')

    last_value = 0
    last_lit301_value = -1
    update_last_lit301 = True
    n_steps = 32
    data = []
    cols = ['FIT201', 'FIT301', 'LIT301', 'FIT_Diff', 'LIT_Diff']

    file_name = 'AllData_' + str(int(time.time())) + '.csv'
    with open(file_name, 'a', newline='', buffering=1) as csvfile:
        print("starting while true loop....")
        while True:
            plant_state = detector.getState()
            w = csv.DictWriter(csvfile, plant_state.keys())
            if last_value == 0:
                w.writeheader()

            if last_lit301_value != -1:
                lit_diff = plant_state['LIT301'] - last_lit301_value
                data.append([plant_state['FIT201'], plant_state['FIT301'], plant_state['LIT301'],
                             plant_state['FIT201'] - plant_state['FIT301'], lit_diff])
                print(data[-1])

                if len(data) >= n_steps:
                    df = pd.DataFrame(data, columns=cols)
                    df[cols[:-1]] = x_scaler.transform(df[cols[:-1]])
                    df[cols[-1]] = y_scaler.transform(df[cols[-1]].values.reshape(-1, 1))
                    X, y = split_sequences(df.values, n_steps)
                    loss, mse, mae = model.evaluate(X, y, verbose=0)
                    print(loss, mse, mae)
                    y_pred = model.predict(X)
                    y_inv = y_scaler.inverse_transform(y.reshape(-1, 1))
                    y_pred_inv = y_scaler.inverse_transform(y_pred.reshape(-1, 1))
                    print(f" Predicted LIT301-Diff:{y_pred_inv[-1][0]}, Published LIT301-Diff:{y_inv[-1][0]}, "
                          f" Error:{abs(y_pred_inv[-1][0]-y_inv[-1][0])}")

                    # last value of LIT need to be corrected as per prediction
                    # df[cols[-1]][-1] = df[cols[-1]][-2]+y_pred_inv[-1][0]
                    if (abs(y_pred_inv[-1][0] - y_inv[-1][0])) > 1:
                        print("**********************Seems to be in Attack Mode for LIT301**********************")
                        data.pop()
                        data.append([plant_state['FIT201'], plant_state['FIT301'], last_lit301_value+y_pred_inv[-1][0],
                             plant_state['FIT201'] - plant_state['FIT301'], y_pred_inv[-1][0]])

                        print(
                            f"Updating  last_lit301_value{last_lit301_value} using Prediction  {last_lit301_value+y_pred_inv[-1][0]},")
                        last_lit301_value = last_lit301_value+y_pred_inv[-1][0]
                        update_last_lit301 = False
                    else:
                        data.pop(0)
                        update_last_lit301 = True

            if update_last_lit301:
                print(f"Updating  last_lit301_value{last_lit301_value} plant_state['LIT301']  {plant_state['LIT301']},")
                last_lit301_value = plant_state['LIT301']


            print(f"UV401-{plant_state['UV401']}, "
                  f" P401={plant_state['P401']}, "
                  f" P501={plant_state['P501']}, "
                  f" AIT402={plant_state['AIT402']}")

            if (last_value != 0 and
                    plant_state['UV401'] != 2 and
                    plant_state['P401'] == 2):
                print("**********************Seems to be in Attack Mode for UV401**********************")

            print(f"P401-{plant_state['P401']}, "
                  f" P402={plant_state['P402']}, "
                  f" FIT301={plant_state['FIT301']}, "
                  f" MV302={plant_state['MV302']} "
                  f" LIT401={plant_state['LIT401']} "
                  f" diff={last_value - plant_state['LIT401']}")

            if (last_value != 0 and
                    plant_state['P401'] != 2 and
                    plant_state['P402'] != 2 and
                    plant_state['MV302'] == 2 and
                    plant_state['FIT301'] >= 1 >= (last_value - plant_state['LIT401'])):
                print("**********************Seems to be in Attack Mode on LIT401**********************")

            last_value = plant_state['LIT401']

            w.writerow(plant_state)
            csvfile.flush()


if __name__ == '__main__':
    main()

"""  
detAEGIS=DetZMQ(detector="AEGIS", detObj={"ID": "AEGIS", "Anomaly": True, "Invariant": ["I1"]})
detAEGIS.setup()

detAICrit=DetZMQ(detector="AICrit", detObj={"ID": "AICrit", "Anomaly": True, "Invariant": ["I1"]})
detAICrit.setup()
count=0
while count<10:
    detAEGIS.getState()
    detObj=detAEGIS.detObj
    detAEGIS.publishDetObj(detObj)

    detAICrit.getState()
    detObj=detAICrit.detObj
    detAICrit.publishDetObj(detObj)
    count+=1

detAEGIS.closeSockets()
detAICrit.closeSockets()
print("Sockets closed")
"""
