#![cfg(feature = "python-oracle-tests")]
// Optional parity tests against Python Reticulum helpers.
// Enable with:
//   cargo test --release --features python-oracle-tests --test python_oracle

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyTuple;
use std::path::PathBuf;

fn init_python(py: Python<'_>) {
    let sys = py.import("sys").unwrap();
    let path: &pyo3::types::PyList = sys.getattr("path").unwrap().downcast().unwrap();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let reticulum_master = manifest_dir.parent().unwrap().join("Reticulum-master");
    path.insert(0, reticulum_master.to_str().unwrap()).unwrap();
}

fn call_rns_func(py: Python<'_>, func: &str, args: Vec<PyObject>) -> PyObject {
    init_python(py);
    let rns = py.import("RNS").unwrap();
    let callable = rns.getattr(func).unwrap();
    let tuple = PyTuple::new(py, args);
    callable.call1(tuple).unwrap().into()
}

#[test]
fn test_hexrep() {
    let data = vec![0u8, 1, 2, 255];
    let expected = Python::with_gil(|py| {
        let args = vec![PyBytes::new(py, &data).into_py(py), true.into_py(py)];
        call_rns_func(py, "hexrep", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::hexrep(&data, true);
    assert_eq!(actual, expected);
}

#[test]
fn test_prettyhexrep() {
    let data = vec![0u8, 1, 2, 255];
    let expected = Python::with_gil(|py| {
        let args = vec![PyBytes::new(py, &data).into_py(py)];
        call_rns_func(py, "prettyhexrep", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::prettyhexrep(&data);
    assert_eq!(actual, expected);
}

#[test]
fn test_prettysize() {
    let expected = Python::with_gil(|py| {
        let args = vec![12345.0.into_py(py), "B".into_py(py)];
        call_rns_func(py, "prettysize", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::prettysize(12345.0, "B");
    assert_eq!(actual, expected);
}

#[test]
fn test_prettytime() {
    let expected = Python::with_gil(|py| {
        let args = vec![3661.5.into_py(py), false.into_py(py), false.into_py(py)];
        call_rns_func(py, "prettytime", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::prettytime(3661.5, false, false);
    assert_eq!(actual, expected);
}

#[test]
fn test_prettyshorttime() {
    let expected = Python::with_gil(|py| {
        let args = vec![0.001234.into_py(py), false.into_py(py), false.into_py(py)];
        call_rns_func(py, "prettyshorttime", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::prettyshorttime(0.001234, false, false);
    assert_eq!(actual, expected);
}

#[test]
fn test_prettyfrequency() {
    let expected = Python::with_gil(|py| {
        let args = vec![1.234.into_py(py), "Hz".into_py(py)];
        call_rns_func(py, "prettyfrequency", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::prettyfrequency(1.234, "Hz");
    assert_eq!(actual, expected);
}

#[test]
fn test_prettydistance() {
    let expected = Python::with_gil(|py| {
        let args = vec![0.000123.into_py(py), "m".into_py(py)];
        call_rns_func(py, "prettydistance", args)
            .extract::<String>(py)
            .unwrap()
    });
    let actual = reticulum_rust::prettydistance(0.000123, "m");
    assert_eq!(actual, expected);
}
