from typing import List, Dict, Any
import numpy as np
from scipy.spatial.distance import euclidean
from operator import itemgetter
import json


def knncalc(data: Dict[str, Any]):
    my_info = np.array(list(data["myinfo"].values()))
    users = {}
    for key in data["users"].keys():
        users[key] = np.array(list(data["users"][key].values()))

    # knn 알고리즘 적용
    distances = {}
    for key in users.keys():
        distances[key] = euclidean(my_info, users[key])
    sorted_distances = sorted(distances.items(), key=itemgetter(1))

    # 결과 반환
    result = []
    for i in sorted_distances:
        result.append(int(i[0]))

    response = {
        "userList": result
    }

    return response